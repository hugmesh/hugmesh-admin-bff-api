package net.hugmesh.adminbff.imagegen;

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
import net.hugmesh.adminbff.web.dto.ImageBuildIngestRequest;
import net.hugmesh.adminbff.web.dto.ImageBuildProgressRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The IN-CLUSTER image-gen Job's completion-report endpoint. Mounted under
 * {@code /bff/internal/**} (the in-cluster node/Job-to-BFF surface): NO human JWT — {@code
 * SecurityConfig} gates the prefix to {@code ROLE_SERVICE}, which the Job satisfies with the
 * env-injected {@code X-Internal-Token}, on top of the in-cluster mTLS transport in production
 * ({@code server.ssl.client-auth=need} — only a caller holding a cert chaining to the cluster
 * CA completes the handshake) and auth-core's {@code InternalTokenWebFilter} (same header,
 * fail-closed when configured). It is therefore
 * authenticated as the Job's ServiceAccount/in-cluster identity, NOT publicly callable, and NOT
 * an admin endpoint — distinct from the test-reports ingest (which is admin-token-gated).
 *
 * <p><b>NO-SECRET CONTRACT.</b> The {@link ImageBuildIngestRequest} body has NO private-key
 * field and the service reads none. This endpoint writes only the NON-SECRET rows
 * (device_registry identity + device_ssh_dial fingerprints / public keys / Vault POINTERS) and
 * the (non-secret) artifact pointers + terminal status. A private dial key never reaches the
 * BFF — it lives only in Vault and is mounted into the device via ESO.
 */
@RestController
@RequestMapping("/bff/internal/image-builds")
@Validated
public class ImageBuildIngestController {

    private static final int MAX_ID = 36;

    private final ImageBuildService service;

    public ImageBuildIngestController(ImageBuildService service) {
        this.service = service;
    }

    @Operation(summary = "Ingest", operationId = "imageBuildIngestIngest")
    @PostMapping("/{id}/ingest")
    public Mono<Map<String, Object>> ingest(
            @PathVariable @NotBlank @Size(max = MAX_ID) String id,
            @Valid @RequestBody ImageBuildIngestRequest in) {
        return service.ingest(id, in)
                .map(b -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("id", b.id());
                    out.put("status", b.status());
                    out.put("imageRef", b.imageRef());
                    out.put("keysRef", b.keysRef());
                    return out;
                });
    }

    /**
     * NON-TERMINAL progress leg (worklist redesign item 8) — DISJOINT from the terminal
     * {@code /ingest} mapping. The in-cluster Job POSTs 0..N of these while a build runs; each fans
     * an SSE {@code progress} frame ({@code done=false}) WITHOUT closing the sink or stamping
     * {@code finished_at}. The single terminal {@code /ingest} still closes the build (and is now
     * idempotent — a second terminal POST is a 200 no-op). Same internal (mTLS + internal-token)
     * boundary as {@code /ingest}; NOT an admin endpoint, NO JWT.
     */
    @Operation(summary = "Progress", operationId = "imageBuildIngestProgress")
    @PostMapping("/{id}/progress")
    public Mono<Map<String, Object>> progress(
            @PathVariable @NotBlank @Size(max = MAX_ID) String id,
            @Valid @RequestBody ImageBuildProgressRequest in) {
        return service.progress(id, in)
                .thenReturn(Map.of("id", id, "accepted", true));
    }
}
