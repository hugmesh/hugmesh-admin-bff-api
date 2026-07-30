package systems.hugmesh.adminbff.imagegen;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.sshterminal.ImageBuild;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the WORKLIST BATCH endpoint {@code POST /bff/admin/image-builds/batch}
 * (worklist redesign item 1): ADMIN/SUPERADMIN gating, jakarta bean-validation 400s (schema
 * discriminator, N&le;16 @Size cap, per-entry platform enum), the {batchId, builds[]} response
 * shape, and the X-ImageGen-StepUp + bff_session plumbing. The service is mocked; the fail-closed
 * envelope validator + own-domain wall + single-MFA-consume BEHAVIOUR lives in the service tests.
 */
@WebFluxTest(controllers = {ImageBuildController.class})
@Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class})
class BatchTriggerImageBuildControllerTest {

    @Autowired ApplicationContext context;
    WebTestClient web;

    @BeforeEach
    void setUp() {
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

    private static ImageBuild queued(String id, String type) {
        return new ImageBuild(id, Instant.now(), "admin@acme", "user@acme", "acme",
                type, "rpi5", null, ImageBuild.STATUS_QUEUED, false,
                null, null, null, null, null, null);
    }

    private static final String VALID_BODY = "{\"schema\":\"hugmesh-worklist/v1\","
            + "\"entries\":["
            + "{\"targetUser\":\"acme/alice\",\"imageType\":\"primary\",\"hardwareClass\":\"rpi5\"},"
            + "{\"targetUser\":\"acme/bob\",\"imageType\":\"client\",\"hardwareClass\":\"x86\"}"
            + "],\"maxConcurrent\":1}";

    @Test
    void batch_returnsBatchIdAndBuilds() {
        when(service.triggerBatch(any(), any(), any(), any())).thenReturn(Mono.just(
                new ImageBuildService.BatchResult("batch-1",
                        List.of(queued("b1", "primary"), queued("b2", "client")))));
        asAdmin().post().uri("/bff/admin/image-builds/batch").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.batchId").isEqualTo("batch-1")
                .jsonPath("$.builds[0].id").isEqualTo("b1")
                .jsonPath("$.builds[0].status").isEqualTo("QUEUED")
                .jsonPath("$.builds[1].id").isEqualTo("b2")
                .jsonPath("$.builds[1].imageType").isEqualTo("client");
    }

    @Test
    void batch_threadsStepUpHeaderAndSessionCookie() {
        when(service.triggerBatch(any(), any(), eq("stepup-tok"), eq("bff_opaque123")))
                .thenReturn(Mono.just(new ImageBuildService.BatchResult("batch-1", List.of(queued("b1", "primary")))));
        asAdmin().post().uri("/bff/admin/image-builds/batch").contentType(MediaType.APPLICATION_JSON)
                .header(ImageGenStepUpGate.STEP_UP_HEADER, "stepup-tok")
                .cookie("bff_session", "bff_opaque123")
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isOk();
        verify(service).triggerBatch(any(), any(), eq("stepup-tok"), eq("bff_opaque123"));
    }

    @Test
    void batch_wrongSchema_400_andNoServiceCall() {
        String body = VALID_BODY.replace("hugmesh-worklist/v1", "totally/wrong");
        asAdmin().post().uri("/bff/admin/image-builds/batch").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).triggerBatch(any(), any(), any(), any());
    }

    @Test
    void batch_emptyEntries_400() {
        String body = "{\"schema\":\"hugmesh-worklist/v1\",\"entries\":[]}";
        asAdmin().post().uri("/bff/admin/image-builds/batch").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).triggerBatch(any(), any(), any(), any());
    }

    @Test
    void batch_moreThan16Entries_400() {
        StringBuilder sb = new StringBuilder("{\"schema\":\"hugmesh-worklist/v1\",\"entries\":[");
        for (int i = 0; i < 17; i++) {
            if (i > 0) sb.append(',');
            sb.append("{\"targetUser\":\"acme/u").append(i)
                    .append("\",\"imageType\":\"primary\",\"hardwareClass\":\"rpi5\"}");
        }
        sb.append("]}");
        asAdmin().post().uri("/bff/admin/image-builds/batch").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(sb.toString())
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).triggerBatch(any(), any(), any(), any());
    }

    @Test
    void batch_badPlatform_400() {
        String body = VALID_BODY.replace("\"rpi5\"", "\"toaster\"");
        asAdmin().post().uri("/bff/admin/image-builds/batch").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).triggerBatch(any(), any(), any(), any());
    }

    @Test
    void batch_nonAdmin_403() {
        asUser().post().uri("/bff/admin/image-builds/batch").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).triggerBatch(any(), any(), any(), any());
    }

    @Test
    void batch_unauthenticated_401() {
        web.post().uri("/bff/admin/image-builds/batch").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(VALID_BODY)
                .exchange().expectStatus().isUnauthorized();
    }
}
