package net.hugmesh.adminbff.testreports;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the Test-Reports endpoints: ADMIN gating (@PreAuthorize via
 * SecurityConfig's @EnableReactiveMethodSecurity → non-admin 403 / unauthenticated
 * 401), jakarta bean-validation 400s ({error,fields} via ValidationExceptionHandler),
 * the run trigger, the SSE stream, the download headers, and the ingest path. The
 * service is mocked; deeper behaviour is covered in TestReportsServiceTest /
 * TestRunRepositoryTest / TestReportArchiveTest.
 */
@WebFluxTest(controllers = TestReportsController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class,
        net.hugmesh.adminbff.config.LegacyJacksonObjectMapperConfig.class})
class TestReportsControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean TestReportsService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static TestRun run(String id, String tier, String status) {
        return new TestRun(id, Instant.now(), "admin@x", tier, TestRun.SOURCE_ADMIN, status,
                "abc1234", "job-1", Instant.now(), null, 0, 0, 0, 0, null, "lean/run/", null);
    }

    // ── history (list) ───────────────────────────────────────────────────
    @Test
    void history_returnsRunsAndSeamSignal() {
        when(service.history()).thenReturn(Flux.just(run("r1", "LEAN", "COMPLETED")));
        when(service.launchIsReal()).thenReturn(false);
        asAdmin().get().uri("/bff/admin/test-reports").exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.runs[0].id").isEqualTo("r1")
                .jsonPath("$.runs[0].tier").isEqualTo("LEAN")
                .jsonPath("$.runs[0].status").isEqualTo("COMPLETED")
                .jsonPath("$.launchReal").isEqualTo(false);
    }

    @Test
    void history_nonAdmin_403() {
        asUser().get().uri("/bff/admin/test-reports").exchange().expectStatus().isForbidden();
        verify(service, never()).history();
    }

    @Test
    void history_unauthenticated_401() {
        web.get().uri("/bff/admin/test-reports").exchange().expectStatus().isUnauthorized();
    }

    // ── detail ({id}) ─────────────────────────────────────────────────────
    @Test
    void detail_returnsSummaryAndMatrix() {
        TestRunResult res = new TestRunResult("x1", "r1", "19-local-only-mastodon",
                "e2e-mastodon-domainlocked", "passed", 3, 0, 0, 800L, Instant.now());
        when(service.detail("r1")).thenReturn(Mono.just(
                new TestReportsService.TestRunDetail(run("r1", "LEAN", "COMPLETED"), List.of(res))));
        asAdmin().get().uri("/bff/admin/test-reports/r1").exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.run.id").isEqualTo("r1")
                .jsonPath("$.results[0].suite").isEqualTo("19-local-only-mastodon")
                .jsonPath("$.results[0].role").isEqualTo("e2e-mastodon-domainlocked")
                .jsonPath("$.results[0].state").isEqualTo("passed");
    }

    @Test
    void detail_notFound_404() {
        when(service.detail("ghost")).thenReturn(Mono.error(
                ApiException.badRequest("x"))); // any ApiException; use NOT_FOUND below
        when(service.detail("ghost")).thenReturn(Mono.error(
                new ApiException(org.springframework.http.HttpStatus.NOT_FOUND, "test run 'ghost' not found")));
        asAdmin().get().uri("/bff/admin/test-reports/ghost").exchange().expectStatus().isNotFound()
                .expectBody().jsonPath("$.error").value(org.hamcrest.Matchers.containsString("not found"));
    }

    @Test
    void detail_nonAdmin_403() {
        asUser().get().uri("/bff/admin/test-reports/r1").exchange().expectStatus().isForbidden();
    }

    // ── run trigger ───────────────────────────────────────────────────────
    @Test
    void run_lean_returnsIdAndStatus() {
        when(service.triggerRun(anyString(), eq("LEAN"), any())).thenReturn(Mono.just("new-run-1"));
        asAdmin().post().uri("/bff/admin/test-reports/run").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"tier\":\"LEAN\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("new-run-1")
                .jsonPath("$.status").isEqualTo("QUEUED")
                .jsonPath("$.tier").isEqualTo("LEAN");
    }

    @Test
    void run_emptyBody_defaultsLean() {
        when(service.triggerRun(anyString(), eq("LEAN"), any())).thenReturn(Mono.just("new-run-2"));
        asAdmin().post().uri("/bff/admin/test-reports/run")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.tier").isEqualTo("LEAN");
    }

    @Test
    void run_badTier_400_andNoServiceCall() {
        asAdmin().post().uri("/bff/admin/test-reports/run").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"tier\":\"GIGANTIC\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.tier").exists();
        verify(service, never()).triggerRun(anyString(), anyString(), any());
    }

    @Test
    void run_nonAdmin_403() {
        asUser().post().uri("/bff/admin/test-reports/run").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"tier\":\"LEAN\"}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).triggerRun(anyString(), anyString(), any());
    }

    // ── download ──────────────────────────────────────────────────────────
    @Test
    void download_streamsTarGzWithAttachmentHeader() {
        DataBuffer buf = new DefaultDataBufferFactory().wrap("tar-bytes".getBytes(StandardCharsets.UTF_8));
        when(service.download("r1")).thenReturn(Flux.just(buf));
        asAdmin().get().uri("/bff/admin/test-reports/r1/download").exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.parseMediaType("application/gzip"))
                .expectHeader().value("Content-Disposition",
                        org.hamcrest.Matchers.containsString("test-report-r1.tar.gz"));
    }

    @Test
    void download_nonAdmin_403() {
        asUser().get().uri("/bff/admin/test-reports/r1/download").exchange().expectStatus().isForbidden();
        verify(service, never()).download(anyString());
    }

    // ── SSE events ────────────────────────────────────────────────────────
    @Test
    void events_streamsServerSentEvents() {
        when(service.events("r1")).thenReturn(Flux.just(
                TestRunEvent.suite("r1", "19-local-only-mastodon", "e2e-mastodon-domainlocked",
                        "running", 0, 0, 0, 25, "starting"),
                TestRunEvent.complete("r1", 40, 0, 2, "done")));
        asAdmin().get().uri("/bff/admin/test-reports/r1/events")
                .accept(MediaType.TEXT_EVENT_STREAM)
                .exchange().expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith(MediaType.TEXT_EVENT_STREAM);
    }

    @Test
    void events_nonAdmin_403() {
        asUser().get().uri("/bff/admin/test-reports/r1/events")
                .accept(MediaType.TEXT_EVENT_STREAM)
                .exchange().expectStatus().isForbidden();
    }

    // ── ingest (test-runner event path) ───────────────────────────────────
    @Test
    void ingest_suiteEvent_returnsRollup() {
        when(service.ingest(eq("r1"), any())).thenReturn(Mono.just(run("r1", "LEAN", "RUNNING")));
        asAdmin().post().uri("/bff/admin/test-reports/r1/ingest").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"SUITE\",\"suite\":\"19-local-only-mastodon\","
                        + "\"role\":\"e2e-mastodon-domainlocked\",\"state\":\"passed\","
                        + "\"passed\":3,\"failed\":0,\"skipped\":0,\"percent\":50}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("r1").jsonPath("$.status").isEqualTo("RUNNING");
    }

    @Test
    void ingest_badState_400() {
        asAdmin().post().uri("/bff/admin/test-reports/r1/ingest").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"SUITE\",\"suite\":\"s\",\"state\":\"exploded\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.state").exists();
        verify(service, never()).ingest(anyString(), any());
    }

    @Test
    void ingest_nonAdmin_403() {
        asUser().post().uri("/bff/admin/test-reports/r1/ingest").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"RUN\",\"state\":\"passed\"}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).ingest(anyString(), any());
    }
}
