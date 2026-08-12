package net.hugmesh.adminbff.imagegen;
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
import net.hugmesh.adminbff.sshterminal.ImageBuild;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.adminbff.web.dto.ImageBuildProgressRequest;

import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the admin image-gen endpoints: ADMIN/SUPERADMIN gating (@PreAuthorize
 * via SecurityConfig → non-admin 403 / unauthenticated 401), jakarta bean-validation 400s, the
 * trigger, the SSE stream, and the download headers. The service is mocked here; the fail-closed
 * own-domain wall + step-up + keys-gating BEHAVIOUR is covered in {@link ImageBuildServiceTest}.
 */
@WebFluxTest(controllers = {ImageBuildController.class, ImageBuildIngestController.class})
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class})
class ImageBuildControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ImageBuildService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static ImageBuild build(String id, String status, boolean keys) {
        return new ImageBuild(id, Instant.now(), "admin@acme", "user@acme", "acme",
                ImageBuild.IMAGE_PRIMARY, "rpi5", null, status, keys,
                "job-1", "build-" + id + "/image.img", keys ? "build-" + id + "/keys.tar.gz" : null,
                Instant.now(), null, null);
    }

    // ── trigger ───────────────────────────────────────────────────────────
    @Test
    void trigger_returnsQueued() {
        when(service.trigger(any(), any(), any(), any())).thenReturn(Mono.just(build("b1", ImageBuild.STATUS_QUEUED, false)));
        asAdmin().post().uri("/bff/admin/image-builds").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"targetUser\":\"user@acme\",\"imageType\":\"primary\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("b1")
                .jsonPath("$.status").isEqualTo("QUEUED")
                .jsonPath("$.imageType").isEqualTo("primary");
    }

    @Test
    void trigger_threadsBffSessionCookieAsSessionToken() {
        // The controller derives the opaque bff_ session token from the bff_session cookie (the
        // SessionCookieWebFilter idiom) and threads it to the service as the 4th arg — proving the
        // co-equal MFA leg gets the caller's session, never a body/path field.
        when(service.trigger(any(), any(), any(), eq("bff_opaque123")))
                .thenReturn(Mono.just(build("b1", ImageBuild.STATUS_QUEUED, false)));
        asAdmin().post().uri("/bff/admin/image-builds").contentType(MediaType.APPLICATION_JSON)
                .cookie("bff_session", "bff_opaque123")
                .bodyValue("{\"targetUser\":\"user@acme\",\"imageType\":\"primary\"}")
                .exchange().expectStatus().isOk();
        verify(service).trigger(any(), any(), any(), eq("bff_opaque123"));
    }

    @Test
    void trigger_badImageType_400_andNoServiceCall() {
        asAdmin().post().uri("/bff/admin/image-builds").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"targetUser\":\"u\",\"imageType\":\"toaster\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.imageType").exists();
        verify(service, never()).trigger(any(), any(), any(), any());
    }

    @Test
    void trigger_missingTargetUser_400() {
        asAdmin().post().uri("/bff/admin/image-builds").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"imageType\":\"primary\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.targetUser").exists();
        verify(service, never()).trigger(any(), any(), any(), any());
    }

    @Test
    void trigger_nonAdmin_403() {
        asUser().post().uri("/bff/admin/image-builds").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"targetUser\":\"user@acme\",\"imageType\":\"primary\"}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).trigger(any(), any(), any(), any());
    }

    @Test
    void trigger_unauthenticated_401() {
        web.post().uri("/bff/admin/image-builds").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"targetUser\":\"user@acme\",\"imageType\":\"primary\"}")
                .exchange().expectStatus().isUnauthorized();
    }

    // ── history ───────────────────────────────────────────────────────────
    @Test
    void history_returnsBuildsAndSeamSignal() {
        when(service.history(any(), anyInt())).thenReturn(Flux.just(build("b1", ImageBuild.STATUS_COMPLETED, false)));
        when(service.launchIsReal()).thenReturn(false);
        asAdmin().get().uri("/bff/admin/image-builds").exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.builds[0].id").isEqualTo("b1")
                .jsonPath("$.launchReal").isEqualTo(false);
    }

    @Test
    void history_nonAdmin_403() {
        asUser().get().uri("/bff/admin/image-builds").exchange().expectStatus().isForbidden();
        verify(service, never()).history(any(), anyInt());
    }

    // ── SSE ─────────────────────────────────────────────────────────────────
    @Test
    void events_streamsServerSentEvents() {
        when(service.events(any(), eq("b1"))).thenReturn(Flux.just(
                ImageBuildEvent.progress("b1", 10, "partitioning"),
                ImageBuildEvent.complete("b1", "build-b1/image.img", null, "done")));
        asAdmin().get().uri("/bff/admin/image-builds/b1/events")
                .accept(MediaType.TEXT_EVENT_STREAM)
                .exchange().expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith(MediaType.TEXT_EVENT_STREAM);
    }

    @Test
    void events_nonAdmin_403() {
        asUser().get().uri("/bff/admin/image-builds/b1/events")
                .accept(MediaType.TEXT_EVENT_STREAM)
                .exchange().expectStatus().isForbidden();
    }

    // ── image download ────────────────────────────────────────────────────
    @Test
    void imageDownload_streamsWithAttachmentHeader() {
        DataBuffer buf = new DefaultDataBufferFactory().wrap("img-bytes".getBytes(StandardCharsets.UTF_8));
        when(service.downloadImage(any(), eq("b1"))).thenReturn(Flux.just(buf));
        asAdmin().get().uri("/bff/admin/image-builds/b1/image").exchange()
                .expectStatus().isOk()
                .expectHeader().value("Content-Disposition",
                        org.hamcrest.Matchers.containsString("hugmesh-image-b1.img"));
    }

    @Test
    void imageDownload_nonAdmin_403() {
        asUser().get().uri("/bff/admin/image-builds/b1/image").exchange().expectStatus().isForbidden();
        verify(service, never()).downloadImage(any(), anyString());
    }

    // ── keys download (web layer; deeper gating in ImageBuildServiceTest) ──
    @Test
    void keysDownload_streamsWithAttachmentHeader() {
        DataBuffer buf = new DefaultDataBufferFactory().wrap("keys".getBytes(StandardCharsets.UTF_8));
        when(service.downloadKeys(any(), eq("b1"), any(), any())).thenReturn(Flux.just(buf));
        asAdmin().get().uri("/bff/admin/image-builds/b1/keys").exchange()
                .expectStatus().isOk()
                .expectHeader().value("Content-Disposition",
                        org.hamcrest.Matchers.containsString("hugmesh-keys-b1.tar.gz"));
    }

    @Test
    void keysDownload_forbiddenSurfacesAs403() {
        when(service.downloadKeys(any(), eq("b1"), any(), any()))
                .thenReturn(Flux.error(ApiException.forbidden("ssh keys were not enabled for this build")));
        asAdmin().get().uri("/bff/admin/image-builds/b1/keys").exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void keysDownload_nonAdmin_403() {
        asUser().get().uri("/bff/admin/image-builds/b1/keys").exchange().expectStatus().isForbidden();
        verify(service, never()).downloadKeys(any(), anyString(), any(), any());
    }

    // ── ingest is INTERNAL (no JWT) — not an admin endpoint ─────────────────
    @Test
    void ingest_internalPath_isReachableWithoutJwt() {
        when(service.ingest(eq("b1"), any())).thenReturn(Mono.just(build("b1", ImageBuild.STATUS_COMPLETED, false)));
        web.post().uri("/bff/internal/image-builds/b1/ingest").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"status\":\"COMPLETED\",\"imageRef\":\"build-b1/image.img\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("b1");
    }

    @Test
    void ingest_rejectsUnknownStatus_400() {
        web.post().uri("/bff/internal/image-builds/b1/ingest").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"status\":\"RUNNING\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.status").exists();
        verify(service, never()).ingest(anyString(), any());
    }

    // ── progress is INTERNAL (no JWT) — mirrors the real progress-tap.py wire shape ────────
    // (buildId/percent-nullable/phaseIndex/phaseCount/phaseLabel/indeterminate — NOT a
    // percent/phase/message shape; see ImageBuildProgressRequest's design note).
    @Test
    void progress_internalPath_isReachableWithoutJwt_andParsesTheRealWorkerShape() {
        when(service.progress(eq("b1"), any())).thenReturn(Mono.empty());
        // the INITIAL indeterminate frame progress-tap.py sends before any "==>" banner is seen:
        // percent is JSON null, phaseIndex=-1, phaseLabel="". The extra "buildId" key (which the
        // real worker DOES send, redundant with the path {id}) must be tolerated, not rejected.
        web.post().uri("/bff/internal/image-builds/b1/progress").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"buildId\":\"b1\",\"percent\":null,\"phaseIndex\":-1,"
                        + "\"phaseCount\":18,\"phaseLabel\":\"\",\"indeterminate\":true}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("b1")
                .jsonPath("$.accepted").isEqualTo(true);

        ArgumentCaptor<ImageBuildProgressRequest> captor = ArgumentCaptor.forClass(ImageBuildProgressRequest.class);
        verify(service).progress(eq("b1"), captor.capture());
        ImageBuildProgressRequest parsed = captor.getValue();
        assertThat(parsed.percent()).isNull();
        assertThat(parsed.phaseIndex()).isEqualTo(-1);
        assertThat(parsed.phaseCount()).isEqualTo(18);
        assertThat(parsed.phaseLabel()).isEmpty();
        assertThat(parsed.indeterminate()).isTrue();
    }

    @Test
    void progress_midBuildFrame_parsesDeterminatePercentAndLabel() {
        when(service.progress(eq("b1"), any())).thenReturn(Mono.empty());
        web.post().uri("/bff/internal/image-builds/b1/progress").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"buildId\":\"b1\",\"percent\":42,\"phaseIndex\":5,"
                        + "\"phaseCount\":18,\"phaseLabel\":\"Emerge packages\","
                        + "\"indeterminate\":false}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.accepted").isEqualTo(true);

        ArgumentCaptor<ImageBuildProgressRequest> captor = ArgumentCaptor.forClass(ImageBuildProgressRequest.class);
        verify(service).progress(eq("b1"), captor.capture());
        assertThat(captor.getValue().percent()).isEqualTo(42);
        assertThat(captor.getValue().phaseLabel()).isEqualTo("Emerge packages");
    }

    @Test
    void progress_rejectsOutOfRangePercent_400() {
        web.post().uri("/bff/internal/image-builds/b1/progress").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"percent\":150,\"phaseIndex\":2,\"phaseCount\":18,"
                        + "\"phaseLabel\":\"Kernel\",\"indeterminate\":false}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.percent").exists();
        verify(service, never()).progress(anyString(), any());
    }

    private static int anyInt() {
        return org.mockito.ArgumentMatchers.anyInt();
    }
}
