package net.hugmesh.adminbff.tor;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.web.dto.TorOnionReportRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Where a tor-selected node reports the onion hostnames it exports
 * (hugmesh-admin-bff-api#108): {@code POST /bff/internal/tor/onions}.
 *
 * <h3>Transport: the one already trusted for node facts</h3>
 * {@code /bff/internal/**} is {@code hasRole("SERVICE")} in {@code SecurityConfig}, which the
 * node satisfies with the in-cluster {@code X-Internal-Token} on top of the mTLS transport,
 * exactly like {@code POST /bff/internal/device-enrollment/self-report}. No human JWT. No new
 * transport was added for this.
 *
 * <h3>Telemetry, not authority</h3>
 * Any holder of the internal credential can report for any fingerprint (the same known
 * residual as the self-report), so the report writes only {@code tor_node_report} and
 * nothing reads it to decide access. The ACK is minimal: accepted + this fingerprint's own
 * report count. A value the node agent could not have exported is a 422.
 */
@RestController
@RequestMapping("/bff/internal/tor")
@Validated
public class TorInternalController {

    private static final Logger log = LoggerFactory.getLogger(TorInternalController.class);

    private final TorNodeService nodes;

    public TorInternalController(TorNodeService nodes) {
        this.nodes = nodes;
    }

    @Operation(summary = "Report node onions", operationId = "torInternalReportOnions")
    @PostMapping("/onions")
    public Mono<Map<String, Object>> reportOnions(@Valid @RequestBody TorOnionReportRequest body) {
        return nodes.report(body.machineKeyFp(), body.primary(), body.domains())
                .doOnNext(r -> log.info("[tor] onion report fp={} primary={} domains={} count={}",
                        r.machineKeyFp(), r.primaryOnion() != null, r.domainOnions().keySet(),
                        r.reportCount()))
                .map(r -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("accepted", Boolean.TRUE);
                    out.put("reportCount", r.reportCount());
                    return out;
                });
    }
}
