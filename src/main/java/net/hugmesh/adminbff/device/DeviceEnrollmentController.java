package net.hugmesh.adminbff.device;

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
import net.hugmesh.adminbff.web.dto.SelfReportRequest;

import java.util.Map;

/**
 * The node LIVENESS-RECONCILIATION self-report endpoint for the machine_key_fp AUTO-CAPTURE
 * flow. A node POSTs once at first boot (after {@code tailscale up}) recording the fingerprint
 * IT believes it baked + reconciliation hints, so a superadmin can cross-check the node's
 * self-claim against what headscale reports when picking from the pending list.
 *
 * <h3>SECURITY — mTLS, NO JWT, NO AUTHORIZING DATA</h3>
 * This deliberately lives OUTSIDE {@code /bff/admin/**} (whose coarse gate requires an
 * ADMIN/SUPERADMIN JWT) under {@code /bff/internal/**}, which {@code SecurityConfig} gates to
 * {@code ROLE_SERVICE} — the node presents the in-cluster {@code X-Internal-Token} (promoted to
 * a SERVICE principal), on top of the mTLS transport in production
 * ({@code server.ssl.client-auth=need} — only a caller holding a cert that chains to the
 * cluster CA completes the handshake). It takes NO human JWT and writes NO authorizing columns (no
 * owner, no domain, no license, no role). A node self-claim is trivially spoofable, so it can
 * NEVER confer access — authorization is governed entirely by {@code device_registry} +
 * {@code device_ssh_license}, assigned by a SUPERADMIN. This channel only writes reconciliation
 * telemetry (incrementing a per-fp report counter so a runaway is an investigable DoS signal;
 * the mTLS principal breadth is a known residual).
 */
@RestController
@RequestMapping("/bff/internal/device-enrollment")
@Validated
public class DeviceEnrollmentController {

    private static final Logger log = LoggerFactory.getLogger(DeviceEnrollmentController.class);

    private final DeviceEnrollmentService service;

    public DeviceEnrollmentController(DeviceEnrollmentService service) {
        this.service = service;
    }

    /**
     * Record (UPSERT) a node liveness self-report. Returns {@code {accepted:true, reportCount}}
     * — a deliberately MINIMAL acknowledgement that leaks nothing about the registry/licenses
     * (the node learns its own report count, nothing else). No JWT; mTLS is the transport gate.
     */
    @Operation(summary = "Self report", operationId = "deviceEnrollmentSelfReport")
    @PostMapping("/self-report")
    public Mono<ResponseEntity<Map<String, Object>>> selfReport(@Valid @RequestBody SelfReportRequest b) {
        return service.record(b.machineKeyFp(), b.hostname(), b.meshId(), b.tailnetId())
                .doOnNext(e -> log.info("[device-enrollment] self-report fp={} host={} mesh={} count={}",
                        e.machineKeyFp(), e.hostname(), e.meshId(), e.reportCount()))
                .map(e -> ResponseEntity.ok(Map.of(
                        "accepted", Boolean.TRUE,
                        "reportCount", e.reportCount())));
    }
}
