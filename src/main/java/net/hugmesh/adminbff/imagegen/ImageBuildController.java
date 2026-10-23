package net.hugmesh.adminbff.imagegen;

import net.hugmesh.adminbff.mfa.PrincipalSessionToken;
import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.adminbff.sshterminal.ImageBuild;
import net.hugmesh.adminbff.web.dto.BatchTriggerImageBuildRequest;
import net.hugmesh.adminbff.web.dto.TriggerImageBuildRequest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ADMIN/SUPERADMIN image-generation console backend (reactive WebFlux) — clone of the proven
 * test-reports pattern ({@code TestReportsController}): trigger a build, stream SSE progress,
 * download the built image (+ optionally the non-secret SSH-keys bundle).
 *
 * <p><b>Defence-in-depth gating.</b> The gateway denies {@code /bff/admin/**} to non-admins,
 * {@code SecurityConfig.commonRoutes} re-applies {@code hasAnyRole('ADMIN','SUPERADMIN')} on the
 * path, AND {@code @PreAuthorize} re-checks at every method here. On TOP of the role floor, the
 * {@link ImageBuildService} enforces the FAIL-CLOSED own-domain wall (an admin may build only for
 * a target user in their own validated-issuer domain; a superadmin may build cross-domain) and a
 * step-up requirement for the trigger + keys-download.
 *
 * <ul>
 *   <li>{@code GET  /bff/admin/image-builds} — recent build history + the dark-shipping signal.</li>
 *   <li>{@code GET  /bff/admin/image-builds/{id}} — one build row (own-domain scoped).</li>
 *   <li>{@code POST /bff/admin/image-builds} — trigger a build (own-domain wall + step-up).</li>
 *   <li>{@code GET  /bff/admin/image-builds/{id}/events} — SSE live progress.</li>
 *   <li>{@code GET  /bff/admin/image-builds/{id}/image} — download the built image.</li>
 *   <li>{@code GET  /bff/admin/image-builds/{id}/keys} — download the NON-SECRET keys bundle
 *       (only when ssh_keys_allowed + step-up).</li>
 * </ul>
 */
@RestController
@RequestMapping("/bff/admin/image-builds")
@Validated
public class ImageBuildController {

    private static final int MAX_ID = 36;
    private static final int LIST_LIMIT = 100;

    private final ImageBuildService service;

    public ImageBuildController(ImageBuildService service) {
        this.service = service;
    }

    // ── history ──────────────────────────────────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "History", operationId = "imageBuildHistory")
    @GetMapping
    public Mono<Map<String, Object>> history(Authentication auth) {
        return service.history(auth, LIST_LIMIT).collectList()
                .map(builds -> Map.of("builds", builds, "launchReal", service.launchIsReal()));
    }

    // ── one build ──────────────────────────────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Detail", operationId = "imageBuildDetail")
    @GetMapping("/{id}")
    public Mono<ImageBuild> detail(
            @PathVariable @NotBlank @Size(max = MAX_ID) String id,
            Authentication auth) {
        return service.detail(auth, id);
    }

    // ── trigger ──────────────────────────────────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Trigger", operationId = "imageBuildTrigger")
    @PostMapping
    public Mono<Map<String, Object>> trigger(
            @Valid @RequestBody TriggerImageBuildRequest body,
            @RequestHeader(value = ImageGenStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        // The caller's opaque bff_ session (cookie OR synthesised-from-bearer), derived exactly as
        // BackupAdminController/DesktopRemoteInstallController do — NEVER a body/path field.
        String sessionToken = PrincipalSessionToken.of(sessionCookie, authHeader);
        return service.trigger(auth, body, stepUpToken, sessionToken)
                .map(b -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("id", b.id());
                    out.put("status", b.status());
                    out.put("imageType", b.imageType());
                    out.put("domain", b.domain());
                    out.put("sshKeysAllowed", b.sshKeysAllowed());
                    return out;
                });
    }

    // ── trigger a WORKLIST BATCH (1..16 images, one step-up) ────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Trigger batch", operationId = "imageBuildTriggerBatch")
    @PostMapping("/batch")
    public Mono<Map<String, Object>> triggerBatch(
            @Valid @RequestBody BatchTriggerImageBuildRequest body,
            @RequestHeader(value = ImageGenStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        // Identical session derivation to the single trigger — the opaque bff_ session (cookie OR
        // synthesised-from-bearer), NEVER a body/path field. ONE step-up authorizes the whole batch.
        String sessionToken = PrincipalSessionToken.of(sessionCookie, authHeader);
        return service.triggerBatch(auth, body, stepUpToken, sessionToken)
                .map(ImageBuildController::batchResponse);
    }

    private static Map<String, Object> batchResponse(ImageBuildService.BatchResult result) {
        List<Map<String, Object>> builds = new ArrayList<>();
        for (ImageBuild b : result.builds()) {
            Map<String, Object> one = new LinkedHashMap<>();
            one.put("id", b.id());
            one.put("status", b.status());
            one.put("imageType", b.imageType());
            one.put("domain", b.domain());
            one.put("sshKeysAllowed", b.sshKeysAllowed());
            builds.add(one);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("batchId", result.batchId());
        out.put("builds", builds);
        return out;
    }

    // ── SSE live progress ──────────────────────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Events", operationId = "imageBuildEvents")
    @GetMapping(value = "/{id}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<ImageBuildEvent>> events(
            @PathVariable @NotBlank @Size(max = MAX_ID) String id,
            Authentication auth) {
        return service.events(auth, id)
                .map(ev -> ServerSentEvent.<ImageBuildEvent>builder(ev)
                        .event(ev.done() ? (ev.error() == null ? "complete" : "error") : "progress")
                        .build());
    }

    // ── download the built image ─────────────────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Image", operationId = "imageBuildImage")
    @GetMapping("/{id}/image")
    public Mono<ResponseEntity<Flux<DataBuffer>>> image(
            @PathVariable @NotBlank @Size(max = MAX_ID) String id,
            Authentication auth) {
        Flux<DataBuffer> body = service.downloadImage(auth, id);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("hugmesh-image-" + safe(id) + ".img").build());
        return Mono.just(ResponseEntity.ok()
                .headers(headers)
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(body));
    }

    // ── download the NON-SECRET keys bundle (only when ssh_keys_allowed + step-up) ──
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Keys", operationId = "imageBuildKeys")
    @GetMapping("/{id}/keys")
    public Mono<ResponseEntity<Flux<DataBuffer>>> keys(
            @PathVariable @NotBlank @Size(max = MAX_ID) String id,
            @RequestHeader(value = ImageGenStepUpGate.STEP_UP_HEADER, required = false) String stepUpToken,
            @CookieValue(name = SessionCookieWebFilter.SESSION_COOKIE, required = false) String sessionCookie,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            Authentication auth) {
        // The caller's opaque bff_ session, derived the same way the wired examples do.
        String sessionToken = PrincipalSessionToken.of(sessionCookie, authHeader);
        Flux<DataBuffer> body = service.downloadKeys(auth, id, stepUpToken, sessionToken);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("hugmesh-keys-" + safe(id) + ".tar.gz").build());
        return Mono.just(ResponseEntity.ok()
                .headers(headers)
                .contentType(MediaType.parseMediaType("application/gzip"))
                .body(body));
    }

    /** Keep the download filename free of path/CRLF surprises. */
    private static String safe(String id) {
        return id.replaceAll("[^A-Za-z0-9._-]", "_");
    }
}
