package systems.hugmesh.adminbff.phone;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.web.dto.PhoneIngestRequest;

import java.util.Map;

/**
 * The MDM phone-ingest endpoint — where {@code scripts/phone-wizard.sh ingest} POSTs its
 * {@code phone-ingest/v1}|{@code v2} record at the end of phone onboarding, closing the loop the
 * wizard's emit-only mode documents ("no dedicated phone-ingest registry endpoint exists
 * yet"). One row per phone in {@code phone_device} (UPSERT by device_id); a SUPERADMIN
 * queries the fleet via {@code /bff/superadmin/phone-devices}.
 *
 * <h3>SECURITY — mTLS, NO JWT, NO AUTHORIZING DATA</h3>
 * This deliberately lives OUTSIDE {@code /bff/admin/**} under {@code /bff/internal/**},
 * which {@code SecurityConfig} gates to {@code ROLE_SERVICE} (the wizard satisfies it with the
 * in-cluster {@code X-Internal-Token} — see below), on top of the in-cluster transport in
 * production: mTLS ({@code server.ssl.client-auth=need} — only a caller holding a cert that
 * chains to the cluster CA completes the handshake; the wizard sends
 * {@code --client-cert/--client-key}) plus the app-layer {@code InternalTokenWebFilter}
 * (X-Internal-Token, fail-closed when configured — the wizard supplies it via
 * {@code --internal-token-file}; without it an ARMED deployment 401s the POST before this
 * controller runs). It takes NO JWT and writes NO
 * authorizing columns (no owner, no license, no grant) — an ingest record is
 * operator-/device-reported and trivially spoofable within the cluster, so it can NEVER
 * confer access; mesh access is governed by headscale + the MDM/DPC policy. This channel
 * only writes fleet inventory (incrementing a per-device ingest counter so a runaway
 * re-ingest is an investigable signal), exactly mirroring
 * {@link systems.hugmesh.adminbff.device.DeviceEnrollmentController}. NO-SECRET
 * CONTRACT: the body carries no passphrases/keys — the enterprise-profile credential stays
 * in the vault-seed escrow; only its custody LABEL rides along.
 */
@RestController
@RequestMapping("/bff/internal/device-registry")
@Validated
public class PhoneIngestController {

    private static final Logger log = LoggerFactory.getLogger(PhoneIngestController.class);

    private final PhoneDeviceService service;

    public PhoneIngestController(PhoneDeviceService service) {
        this.service = service;
    }

    /**
     * Record (UPSERT) a phone-ingest/v1|v2 onboarding record. Returns
     * {@code {accepted:true, ingestCount}} — a deliberately MINIMAL acknowledgement that
     * leaks nothing about the fleet (the caller learns its own ingest count, nothing else).
     * No JWT; the in-cluster transport is the gate.
     */
    @Operation(summary = "Phone ingest", operationId = "deviceRegistryPhoneIngest")
    @PostMapping("/phone-ingest")
    public Mono<ResponseEntity<Map<String, Object>>> ingest(@Valid @RequestBody PhoneIngestRequest b) {
        return service.ingest(b)
                .doOnNext(d -> log.info("[phone-ingest] device={} codename={} os={} count={}",
                        logSafe(d.deviceId()), logSafe(d.codename()), logSafe(d.os()),
                        d.ingestCount()))
                .map(d -> ResponseEntity.ok(Map.of(
                        "accepted", Boolean.TRUE,
                        "ingestCount", d.ingestCount())));
    }

    /**
     * Device-reported fields are validated for LENGTH only (no charset @Pattern — the
     * catalog owns what a codename looks like), so interior control characters survive to
     * this log line, and Logback's default encoder does not escape them — a crafted
     * device_id could otherwise forge whole log records (CWE-117) on a channel the class
     * doc already calls spoofable. Strip ISO control chars before logging; the STORED
     * record keeps the original bytes (the registry is the evidence, the log is not).
     */
    private static String logSafe(String s) {
        return s == null ? null : s.replaceAll("\\p{Cntrl}", "·");
    }
}
