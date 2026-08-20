package net.hugmesh.adminbff.inference;

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
import net.hugmesh.adminbff.web.dto.AioTriageIngestRequest;

import java.util.Map;

/**
 * The IN-CLUSTER signal-collector's entry point into {@link AioTriageService} — the missing
 * CALLER half of the edge-AI AIOps feature (the node/DaemonSet collector tailing
 * Snort/Suricata + AIDE + k8s events hands its batch here; the triage→notify producer was
 * shipped without one, so nothing in-repo drove it).
 *
 * <h3>SECURITY — internal surface, NO JWT</h3>
 * Mounted under {@code /bff/internal/**} (the in-cluster node/Job-to-BFF surface), which
 * {@code SecurityConfig} gates to {@code ROLE_SERVICE} — satisfied by a Casdoor
 * client-credentials SERVICE JWT or by the env-injected {@code X-Internal-Token} (promoted
 * to a SERVICE principal), on top of the in-cluster mTLS transport in production
 * ({@code server.ssl.client-auth=need}) and auth-core's {@code InternalTokenWebFilter}.
 * Deliberately NOT an admin endpoint: the caller is a node agent, not a human, exactly like
 * {@link net.hugmesh.adminbff.phone.PhoneIngestController} and
 * {@link net.hugmesh.adminbff.imagegen.ImageBuildIngestController}.
 *
 * <p><b>Tenancy is the CALLER's concern</b>, the same posture
 * {@link net.hugmesh.adminbff.capability.DomainCapabilityInternalController} states: there is
 * no untrusted principal at this internal hop, so {@code domain} and the admin recipient set
 * ride in the body and this controller performs no cross-tenant check of its own. It only
 * bounds them (a blank tenant or an empty recipient list is a clean 400 rather than the
 * service's {@code IllegalArgumentException}). The service never widens the audience beyond
 * the subjects handed to it.
 *
 * <p><b>Still DARK by default.</b> {@code inference.edge-ai.enabled} defaults {@code false},
 * so on a mesh with no GPU/edge-AI node this endpoint accepts the batch, gets a
 * {@code disabled} sentinel back and emits NOTHING ({@code alerted:0}) — wiring the caller
 * does not turn the feature on.
 */
@RestController
@RequestMapping("/bff/internal/aio-triage")
@Validated
public class AioTriageIngestController {

    private static final Logger log = LoggerFactory.getLogger(AioTriageIngestController.class);

    private final AioTriageService service;

    public AioTriageIngestController(AioTriageService service) {
        this.service = service;
    }

    /**
     * Triage {@code signals} on the edge-AI node and alert the named admins. Returns the
     * MINIMAL ack {@code {accepted:true, alerted:<n>}} — the caller learns how many admins it
     * newly alerted and nothing else about the tenant. Fail-open by construction: a
     * disabled/degraded edge-AI is {@code alerted:0}, not an error, so a stalled inference
     * node never fails the collector's post.
     */
    @Operation(summary = "Ingest a collected infra/NIDS signal batch for edge-AI triage",
            operationId = "aioTriageIngest")
    @PostMapping("/ingest")
    public Mono<Map<String, Object>> ingest(@Valid @RequestBody AioTriageIngestRequest body) {
        return service.triageAndNotify(body.domain(), body.adminSubjects(),
                        body.eventKey(), body.signals())
                .map(alerted -> Map.<String, Object>of("accepted", Boolean.TRUE, "alerted", alerted))
                .doOnNext(ack -> log.info("[aio-ingest] domain={} key={} recipients={} -> {}",
                        logSafe(body.domain()), logSafe(body.eventKey()),
                        body.adminSubjects().size(), ack.get("alerted")));
    }

    /**
     * The collector's fields are validated for LENGTH only, so interior control characters
     * survive to this log line and Logback's default encoder does not escape them — a crafted
     * eventKey could otherwise forge whole log records (CWE-117) on a channel that is, like
     * every other in-cluster ingest, spoofable from inside the cluster. Same guard as
     * {@code PhoneIngestController#logSafe}.
     */
    private static String logSafe(String s) {
        return s == null ? null : s.replaceAll("\\p{Cntrl}", "·");
    }
}
