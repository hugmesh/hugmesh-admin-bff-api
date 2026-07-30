package systems.hugmesh.adminbff.golive;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.web.dto.GoLiveAppliedAckRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The HOST-SIDE go-live agent's applied-ack surface. Mounted under {@code /bff/internal/**}
 * (the in-cluster/host-to-BFF surface): NO human JWT — {@code SecurityConfig}
 * {@code .pathMatchers("/bff/internal/**").hasRole("SERVICE")}, which the agent satisfies with
 * the in-cluster {@code X-Internal-Token}, on top of the mTLS transport in production
 * ({@code server.ssl.client-auth=need}). MIRRORS
 * {@link systems.hugmesh.adminbff.imagegen.ImageBuildIngestController} exactly. This prefix
 * is NEVER exposed publicly by the gateway.
 *
 * <h3>Why this endpoint exists</h3>
 * The go-live switch is a HOST file ({@code /etc/hugmesh/go-live}) the in-cluster BFF can
 * never write — see {@link GoLiveService} class doc. Only the host-side go-live agent, after
 * verifying the {@link GoLiveExportService signed export}, flips that marker. THIS endpoint is
 * how it reports that back, so {@code status='recorded'} can finally advance to {@code
 * 'applied'} and the wizard UI can render {@code applied:true} truthfully — before this
 * existed, an applied intent's BFF row sat at {@code recorded} forever.
 *
 * <h3>Idempotent, not an error surface</h3>
 * A host agent reconciles on a loop and will call this on every cycle until the entry drops
 * out of the export body. "Already applied" / "withdrawn since" / "superseded by a newer
 * intent" (a different id, per the CAS-supersede model) are ALL normal, expected outcomes of a
 * race with the wizard UI — deliberately NOT distinguished from each other here, and NEVER
 * rendered as an HTTP error status: the response is always {@code 200} with an {@code applied}
 * boolean the agent can just poll on. This mirrors {@code DELETE
 * /bff/admin/go-live/intents/{id}}'s {@code {"withdrawn": <bool>, "id": ...}} shape exactly —
 * same "boolean outcome in a 200" idiom, chosen so a friendly retrying poller never has to
 * special-case a 404/409 that isn't actually a failure.
 */
@RestController
@RequestMapping("/bff/internal/go-live")
@Validated
public class GoLiveInternalController {

    private static final int MAX_ID = 36;

    private final GoLiveService service;

    public GoLiveInternalController(GoLiveService service) {
        this.service = service;
    }

    /**
     * {@code POST /bff/internal/go-live/{intentId}/applied-ack} — body {@code {"generation":
     * <the intent's OWN row generation>, "appliedBy": "<host identity, e.g. a node
     * fingerprint>"}}. Response {@code 200} always: {@code {"id": "<intentId>", "applied":
     * <bool>}} — {@code true} = this call won the CAS and flipped the row to {@code applied};
     * {@code false} = no-op (absent id / not currently {@code recorded} / generation mismatch).
     */
    @Operation(summary = "Applied ack", operationId = "goLiveInternalAppliedAck")
    @PostMapping("/{intentId}/applied-ack")
    public Mono<Map<String, Object>> appliedAck(
            @PathVariable @NotBlank @Size(max = MAX_ID) String intentId,
            @Valid @RequestBody GoLiveAppliedAckRequest body) {
        return service.applyAck(intentId, body.generation(), body.appliedBy())
                .map(rowsUpdated -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("id", intentId);
                    out.put("applied", rowsUpdated == 1L);
                    return out;
                });
    }
}
