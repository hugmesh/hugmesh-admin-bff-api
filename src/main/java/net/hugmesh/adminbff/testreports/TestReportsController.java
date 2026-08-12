package net.hugmesh.adminbff.testreports;

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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.web.dto.StartTestRunRequest;
import net.hugmesh.adminbff.web.dto.TestRunIngestRequest;

import java.util.Map;

/**
 * ADMIN-only Test-Reports console backend (reactive WebFlux) — the durable
 * test-architecture run list / report download / on-demand trigger / live SSE
 * progress for the admin-ui {@code test-reports.component}.
 *
 * <p>Admin gating is defence-in-depth identical to the backup feature: the gateway
 * denies {@code /bff/admin/**} to non-admins, the resource-server filter re-applies
 * {@code hasRole('ADMIN')} on the path (see {@code SecurityConfig.commonRoutes}), AND
 * {@code @PreAuthorize("hasRole('ADMIN')")} re-checks at every method here.
 *
 * <ul>
 *   <li>{@code GET  /bff/admin/test-reports} — run history (lean/heavy, timestamps,
 *       pass/fail, tier, source).</li>
 *   <li>{@code GET  /bff/admin/test-reports/{id}} — one run's summary + per-(suite,role)
 *       matrix (the detail view).</li>
 *   <li>{@code GET  /bff/admin/test-reports/{id}/download} — stream the stored report
 *       bundle as a re-scrubbed {@code tar.gz}.</li>
 *   <li>{@code POST /bff/admin/test-reports/run} — trigger a run on-demand (launches
 *       the REAL test-runner Job).</li>
 *   <li>{@code GET  /bff/admin/test-reports/{id}/events} — SSE live PROGRESS stream
 *       (per-suite/per-role running/pass/fail).</li>
 *   <li>{@code POST /bff/admin/test-reports/{id}/ingest} — the in-cluster test-runner's
 *       event-ingest endpoint (admin-token-gated + runner-token; feeds the SSE sink +
 *       the durable matrix).</li>
 * </ul>
 *
 * <p>Validation: jakarta Bean Validation on the typed bodies (@Valid) → clean
 * 400 {error,fields} via the reactive {@code ValidationExceptionHandler};
 * application errors (run not found, tier invalid, traversal ref) are
 * {@code ApiException}s mapped to {@code {error}} by {@code ApiExceptionHandler}.
 */
@RestController
@RequestMapping("/bff/admin/test-reports")
@Validated
public class TestReportsController {

    /** Bounds the {@code {id}} path variable for every id-addressed endpoint. */
    private static final int MAX_ID = 100;

    private final TestReportsService service;

    public TestReportsController(TestReportsService service) {
        this.service = service;
    }

    // ── Run history ─────────────────────────────────────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "History", operationId = "testReportsHistory")
    @GetMapping
    public Mono<Map<String, Object>> history() {
        return service.history().collectList()
                .map(runs -> Map.of("runs", runs, "launchReal", service.launchIsReal()));
    }

    // ── One run: summary + per-(suite,role) matrix ──────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Detail", operationId = "testReportsDetail")
    @GetMapping("/{id}")
    public Mono<TestReportsService.TestRunDetail> detail(
            @PathVariable @NotBlank(message = "id is required")
            @Size(max = MAX_ID, message = "id is too long") String id) {
        return service.detail(id);
    }

    // ── Download the stored report bundle (re-scrubbed tar.gz) ──────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Download", operationId = "testReportsDownload")
    @GetMapping("/{id}/download")
    public Mono<ResponseEntity<Flux<DataBuffer>>> download(
            @PathVariable @NotBlank(message = "id is required")
            @Size(max = MAX_ID, message = "id is too long") String id) {
        // The body Flux resolves the run (404 if missing / 404 if no bundle yet / 400 on
        // a traversal ref) and re-scrubs every text entry on read; the errors surface as
        // the standard {error} body via ApiExceptionHandler when the stream is subscribed.
        Flux<DataBuffer> body = service.download(id);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("test-report-" + safe(id) + ".tar.gz").build());
        return Mono.just(ResponseEntity.ok()
                .headers(headers)
                .contentType(MediaType.parseMediaType("application/gzip"))
                .body(body));
    }

    // ── Trigger a run on-demand (launches the REAL test-runner Job) ─────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Run", operationId = "testReportsRun")
    @PostMapping("/run")
    public Mono<Map<String, Object>> run(@Valid @RequestBody(required = false) StartTestRunRequest b,
                                         Authentication auth) {
        StartTestRunRequest body = (b == null) ? new StartTestRunRequest(null, null) : b;
        return service.triggerRun(actor(auth), body.tierOrLean(), body.commitSha())
                .map(id -> Map.of("id", id, "status", "QUEUED", "tier", body.tierOrLean()));
    }

    // ── SSE live progress (per-suite/per-role running/pass/fail) ────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Events", operationId = "testReportsEvents")
    @GetMapping(value = "/{id}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<TestRunEvent>> events(
            @PathVariable @NotBlank(message = "id is required")
            @Size(max = MAX_ID, message = "id is too long") String id) {
        return service.events(id)
                .map(ev -> ServerSentEvent.<TestRunEvent>builder(ev)
                        .event(ev.done() ? (ev.error() == null ? "complete" : "error") : "progress")
                        .build());
    }

    // ── Event-ingest from the in-cluster test-runner ────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Ingest", operationId = "testReportsIngest")
    @PostMapping("/{id}/ingest")
    public Mono<Map<String, Object>> ingest(
            @PathVariable @NotBlank(message = "id is required")
            @Size(max = MAX_ID, message = "id is too long") String id,
            @Valid @RequestBody TestRunIngestRequest in) {
        return service.ingest(id, in)
                .map(run -> Map.of("id", run.id(), "status", run.status(),
                        "passed", run.passed(), "failed", run.failed(), "skipped", run.skipped()));
    }

    /** The acting admin's identity (JWT subject/name) for {@code triggered_by}. */
    private static String actor(Authentication auth) {
        return auth == null ? "admin" : auth.getName();
    }

    /** Keep the download filename free of path/CRLF surprises. */
    private static String safe(String id) {
        return id.replaceAll("[^A-Za-z0-9._-]", "_");
    }
}
