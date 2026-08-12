package net.hugmesh.adminbff.phone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * The REAL Azure Intune (Microsoft Graph) device-lock leg — wired ONLY when
 * {@code app.phone-lock.azure-intune.enabled=true} (see {@link PhoneLockConfig}); otherwise
 * {@link NoopAzureIntuneLockClient} stands in. The co-equal cloud counterpart to
 * {@link HeadwindDpcLockClient}: it fires ONLY for a device whose DEVICE-REPORTED provider is
 * {@code 'azure-intune'} ({@link #appliesTo}), and like every leg it NEVER hard-fails the
 * aggregate — a rejected command maps to {@link LegOutcome#failed}, a transport/timeout to
 * {@link LegOutcome#unreachable}.
 *
 * <p><b>Lock mechanism (client-credentials → Graph remoteLock).</b> {@link #lock} fetches a
 * confidential-client token ({@code POST {authBaseUrl}/{tenantId}/oauth2/v2.0/token},
 * {@code grant_type=client_credentials}, {@code scope=https://graph.microsoft.com/.default})
 * then issues {@code POST {graphBaseUrl}/deviceManagement/managedDevices/{intuneDeviceId}/remoteLock}
 * with the bearer token. A 2xx is {@link LegOutcome#applied}.
 *
 * <p><b>The unlock ASYMMETRY (documented).</b> Intune has NO native "unlock" verb — a Graph
 * {@code remoteLock} sets/forces the device passcode-lock, which the END USER unlocks on the
 * handset with their credential; the service cannot un-force it remotely. So {@link #unlock} is
 * a DELIBERATE no-op: it issues NO Graph call and reports {@link LegOutcome#disabled} (the
 * control plane still clears its authoritative lock row + records it — the platform "unlock" is
 * a control-plane state change, NOT a handset force-unlock). This is why the aggregate for an
 * Azure unlock degrades rather than claiming APPLIED: the handset was not force-unlocked.
 *
 * <p><b>Secret custody.</b> The confidential-client secret rides ONLY the urlencoded token FORM
 * BODY — NEVER a URL/query, NEVER a log line, NEVER argv. Tokens are never logged either.
 */
public class AzureIntuneLockClient implements PhoneLockLeg {

    private static final Logger log = LoggerFactory.getLogger(AzureIntuneLockClient.class);

    /** The confidential-client scope for app-only Graph access (the {@code .default} of the
     *  app-registration's application permissions). */
    static final String GRAPH_DEFAULT_SCOPE = "https://graph.microsoft.com/.default";

    private final WebClient http;
    private final String tenantId;
    private final String clientId;
    private final String clientSecret;
    private final String graphBaseUrl;
    private final String authBaseUrl;
    private final Duration timeout;

    public AzureIntuneLockClient(WebClient http, String tenantId, String clientId,
                                 String clientSecret, String graphBaseUrl, String authBaseUrl,
                                 long timeoutMs) {
        this.http = http;
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.graphBaseUrl = trimTrailingSlash(graphBaseUrl);
        this.authBaseUrl = trimTrailingSlash(authBaseUrl);
        this.timeout = Duration.ofMillis(timeoutMs > 0 ? timeoutMs : 8000);
    }

    @Override
    public String name() {
        return NoopAzureIntuneLockClient.LEG;
    }

    /** The Intune leg fires ONLY for a device whose reported provider is 'azure-intune'. */
    @Override
    public boolean appliesTo(PhoneDevice device) {
        return PhoneDevice.MDM_PROVIDER_AZURE_INTUNE.equals(device.effectiveMdmProvider());
    }

    @Override
    public Mono<LegOutcome> lock(PhoneDevice device) {
        String intuneId = device.intuneDeviceId();
        if (intuneId == null || intuneId.isBlank()) {
            // No Graph managedDevice id to target — the remoteLock cannot apply; degrade
            // honestly (mirrors the mesh-deny no-hostname case), never a false APPLIED.
            return Mono.just(LegOutcome.unreachable("device has no intune_device_id to remote-lock"));
        }
        return token()
                .flatMap(accessToken -> remoteLock(intuneId, accessToken)
                        .doOnSuccess(o -> log.info(
                                "[phone-lock] intune remoteLock issued for device (gen={})",
                                device.lockGeneration())))
                // A 2xx token response that carried no access_token is a channel-level reject
                // (app-registration misconfigured) — a hard FAILED, not a transient miss.
                .switchIfEmpty(Mono.fromSupplier(() -> {
                    log.warn("[phone-lock] intune token response missing access_token");
                    return LegOutcome.failed("intune token response missing access_token");
                }))
                // A response WITH a status (token endpoint OR remoteLock) = actively REJECTED
                // = hard FAILED. The exception carries no secret (the secret is in the form
                // body, not the URL); we log only the status code.
                .onErrorResume(WebClientResponseException.class, e -> {
                    log.warn("[phone-lock] intune lock rejected: HTTP {}", e.getStatusCode());
                    return Mono.just(LegOutcome.failed("intune HTTP " + e.getStatusCode().value()));
                })
                // No response (transport / timeout) = best-effort UNREACHABLE = degrades.
                .onErrorResume(e -> {
                    log.warn("[phone-lock] intune lock unreachable — degrading: {}", e.toString());
                    return Mono.just(LegOutcome.unreachable(e.toString()));
                });
    }

    /**
     * The DOCUMENTED unlock no-op. Intune has no native unlock verb (a remoteLock is
     * user-unlockable on the handset, never service-un-forced), so this issues NO Graph call
     * and reports {@link LegOutcome#disabled}: the control plane clears its authoritative lock
     * row regardless (the platform "unlock" is a control-plane state change, not a handset
     * force-unlock), and the aggregate degrades rather than falsely claiming APPLIED. Never
     * throws.
     */
    @Override
    public Mono<LegOutcome> unlock(PhoneDevice device) {
        log.info("[phone-lock] intune has no native unlock — control-plane lock cleared, handset "
                + "not force-unlocked (gen={})", device.lockGeneration());
        return Mono.just(LegOutcome.disabled(
                "intune has no native unlock; platform lock cleared, handset not force-unlocked"));
    }

    /** Fetch a client-credentials access token. The secret is in the FORM BODY only. */
    private Mono<String> token() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);   // FORM BODY only — never URL/query/log/argv
        form.add("scope", GRAPH_DEFAULT_SCOPE);
        return http.post()
                .uri(authBaseUrl + "/" + tenantId + "/oauth2/v2.0/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .timeout(timeout)
                // A 2xx token response with a blank/absent access_token completes EMPTY, which
                // lock()'s switchIfEmpty maps to a hard FAILED (deterministic, no exception).
                .flatMap(tr -> (tr.accessToken() == null || tr.accessToken().isBlank())
                        ? Mono.empty()
                        : Mono.just(tr.accessToken()));
    }

    /** Issue the Graph remoteLock for the managedDevice; 2xx → APPLIED. */
    private Mono<LegOutcome> remoteLock(String intuneDeviceId, String accessToken) {
        return http.post()
                .uri(graphBaseUrl + "/deviceManagement/managedDevices/" + intuneDeviceId + "/remoteLock")
                .headers(h -> h.setBearerAuth(accessToken))   // bearer header — never logged
                .retrieve()
                .toBodilessEntity()
                .timeout(timeout)
                .thenReturn(LegOutcome.applied());
    }

    private static String trimTrailingSlash(String s) {
        if (s == null) {
            return "";
        }
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    /** The token endpoint response — only the access_token is read (never logged). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record TokenResponse(@JsonProperty("access_token") String accessToken) {
    }
}
