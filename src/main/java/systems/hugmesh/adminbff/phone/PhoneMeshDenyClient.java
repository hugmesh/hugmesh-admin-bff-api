package systems.hugmesh.adminbff.phone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;

/**
 * The REAL headscale ACL phone-deny leg — wired ONLY when
 * {@code app.phone-lock.mesh-deny.enabled=true} (see {@link PhoneLockConfig}); otherwise
 * {@link NoopPhoneMeshDenyClient} stands in. A locked phone's {@code tailscaleHostname} is
 * denied on the mesh so the handset cannot reach cluster services even before the DPC lock
 * lands. Mirrors {@link systems.hugmesh.adminbff.device.WebClientHeadscalePolicyClient}'s
 * push pattern (Bearer-authenticated policy write, fail-closed, never hard-throws).
 *
 * <p><b>Documented seam / infra-gated.</b> A real deny needs headscale in DB-policy mode
 * ({@code app.registry.headscale-acl} enabled + an API key) AND the phone&rarr;node ACL
 * identity (the tailnet host the deny rule keys on) — the same {@code docs/CANONICAL-FP.md}
 * class of unverified-field caveat the Layer-A ACL push carries. {@link #DENY_PATH} is a
 * documented constant + TODO; the seam, flag, and APPLIED/UNREACHABLE/FAILED mapping are the
 * load-bearing contract. A blank {@code tailscaleHostname} (a no-USB operator-attested
 * onboarding never read one) makes the deny inapplicable &rarr; UNREACHABLE (degrades),
 * never a false APPLIED.
 */
public class PhoneMeshDenyClient implements PhoneLockLeg {

    private static final Logger log = LoggerFactory.getLogger(PhoneMeshDenyClient.class);

    // TODO(mesh-deny): finalise the headscale ACL deny write against a live control node; the
    // phone->node ACL identity is the same unverified canonical-host caveat as the Layer-A push.
    static final String DENY_PATH = "/api/v1/policy/phone-deny";

    private final WebClient http;
    private final String apiKey;
    private final Duration timeout;

    public PhoneMeshDenyClient(WebClient http, String apiKey, long timeoutMs) {
        this.http = http;
        this.apiKey = apiKey;
        this.timeout = Duration.ofMillis(timeoutMs > 0 ? timeoutMs : 8000);
    }

    @Override
    public String name() {
        return NoopPhoneMeshDenyClient.LEG;
    }

    @Override
    public Mono<LegOutcome> lock(PhoneDevice device) {
        return push(device, true);
    }

    @Override
    public Mono<LegOutcome> unlock(PhoneDevice device) {
        return push(device, false);
    }

    /** Push (or clear) the ACL deny for the phone's tailnet host; map to a {@link LegOutcome}. */
    private Mono<LegOutcome> push(PhoneDevice device, boolean deny) {
        String host = device.tailscaleHostname();
        if (host == null || host.isBlank()) {
            // No tailnet identity to deny — the deny cannot apply; degrade honestly.
            return Mono.just(LegOutcome.unreachable("device has no tailscale_hostname to deny"));
        }
        return http.put()
                .uri(DENY_PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .headers(this::applyAuth)
                .bodyValue(Map.of("host", host, "deny", deny, "generation", device.lockGeneration()))
                .retrieve()
                .toBodilessEntity()
                .timeout(timeout)
                .thenReturn(LegOutcome.applied())
                .doOnSuccess(o -> log.info("[phone-lock] mesh-deny {} for host (gen={})",
                        deny ? "denied" : "re-allowed", device.lockGeneration()))
                .onErrorResume(WebClientResponseException.class, e -> {
                    log.warn("[phone-lock] mesh-deny rejected: HTTP {}", e.getStatusCode());
                    return Mono.just(LegOutcome.failed("headscale HTTP " + e.getStatusCode().value()));
                })
                .onErrorResume(e -> {
                    log.warn("[phone-lock] mesh-deny unreachable — degrading: {}", e.toString());
                    return Mono.just(LegOutcome.unreachable(e.toString()));
                });
    }

    /** Add the Bearer API key iff configured (placeholder-only; never inline). */
    private void applyAuth(HttpHeaders h) {
        if (apiKey != null && !apiKey.isBlank()) {
            h.setBearerAuth(apiKey);
        }
    }
}
