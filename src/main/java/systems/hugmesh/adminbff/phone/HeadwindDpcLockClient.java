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
 * The REAL Headwind device-owner DPC lock leg — wired ONLY when
 * {@code app.phone-lock.headwind.enabled=true} (see {@link PhoneLockConfig}); otherwise
 * {@link NoopHeadwindDpcLockClient} stands in. Mirrors {@link
 * systems.hugmesh.adminbff.device.WebClientHeadscalePolicyClient}: a Bearer-authenticated
 * WebClient seam that NEVER hard-fails the aggregate — a rejected command maps to
 * {@link LegOutcome#failed} (the channel actively refused), a transport/timeout to
 * {@link LegOutcome#unreachable} (best-effort, degrades).
 *
 * <p><b>Documented seam / deferred custody.</b> Real-time device-owner lock is pushed to the
 * handset by the Headwind server over its MQTT channel (MQTT:31000) — a deferred infra gap.
 * The BFF only asks the Headwind server to enqueue the command over its {@code /rest} admin
 * surface, and the exact device-command path + the per-device token custody is OPERATOR-side
 * (it lives in the Headwind console, not this BFF). {@link #COMMAND_PATH} is therefore a
 * documented constant + TODO: the SEAM, the flag, and the outcome mapping are what this leg
 * pins; the precise Headwind REST verb is finalised when the console custody is wired.
 */
public class HeadwindDpcLockClient implements PhoneLockLeg {

    private static final Logger log = LoggerFactory.getLogger(HeadwindDpcLockClient.class);

    // TODO(headwind-rest): confirm the exact Headwind admin REST device-command path against a
    // live HMDM server; the device-owner token custody is operator-side (the Headwind console).
    // The seam + flag + APPLIED/UNREACHABLE/FAILED mapping is the load-bearing contract here.
    static final String COMMAND_PATH = "/rest/private/devices/command";

    private final WebClient http;
    private final String apiKey;
    private final Duration timeout;

    public HeadwindDpcLockClient(WebClient http, String apiKey, long timeoutMs) {
        this.http = http;
        this.apiKey = apiKey;
        this.timeout = Duration.ofMillis(timeoutMs > 0 ? timeoutMs : 8000);
    }

    @Override
    public String name() {
        return NoopHeadwindDpcLockClient.LEG;
    }

    /** The Headwind DPC leg fires only for a Headwind device (a null/blank provider folds to
     *  'headwind' — a device that never reported a provider is a Headwind device). */
    @Override
    public boolean appliesTo(PhoneDevice device) {
        return PhoneDevice.MDM_PROVIDER_HEADWIND.equals(device.effectiveMdmProvider());
    }

    @Override
    public Mono<LegOutcome> lock(PhoneDevice device) {
        return command(device, "LOCK");
    }

    @Override
    public Mono<LegOutcome> unlock(PhoneDevice device) {
        return command(device, "UNLOCK");
    }

    /** POST the device-owner {@code verb} command; map the response to a {@link LegOutcome}. */
    private Mono<LegOutcome> command(PhoneDevice device, String verb) {
        return http.post()
                .uri(COMMAND_PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .headers(this::applyAuth)
                // NO-SECRET body: only the device identity + the command verb + the monotonic
                // generation the handset uses to reject a rolled-back (stale) command.
                .bodyValue(Map.of(
                        "deviceId", device.deviceId(),
                        "command", verb,
                        "generation", device.lockGeneration()))
                .retrieve()
                .toBodilessEntity()
                .timeout(timeout)
                .thenReturn(LegOutcome.applied())
                .doOnSuccess(o -> log.info("[phone-lock] headwind DPC {} enqueued for device (gen={})",
                        verb, device.lockGeneration()))
                // A response with a status = the channel actively REJECTED = hard FAILED.
                .onErrorResume(WebClientResponseException.class, e -> {
                    log.warn("[phone-lock] headwind DPC {} rejected: HTTP {}", verb, e.getStatusCode());
                    return Mono.just(LegOutcome.failed("headwind HTTP " + e.getStatusCode().value()));
                })
                // No response (transport / timeout) = best-effort UNREACHABLE = degrades.
                .onErrorResume(e -> {
                    log.warn("[phone-lock] headwind DPC {} unreachable — degrading: {}", verb, e.toString());
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
