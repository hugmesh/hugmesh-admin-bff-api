package systems.hugmesh.adminbff.golive;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;
import systems.hugmesh.commons.security.DomainRegistry;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the HOST-AGENT applied-ack endpoint. The load-bearing security
 * property is that {@code /bff/internal/**} is reachable WITHOUT a Casdoor JWT — the host agent
 * presents the in-cluster {@code X-Internal-Token} against the prefix's {@code ROLE_SERVICE}
 * floor, and this slice leaves that credential UNARMED (dev/test parity) — see the class doc on {@link GoLiveInternalController} and {@link
 * systems.hugmesh.adminbff.imagegen.ImageBuildIngestController}, whose test mirrors this
 * one). The service is mocked so the controller's request-shape/response-shape contract is
 * isolated from the CAS mechanism itself (covered in {@link GoLiveServiceTest} /
 * {@link GoLiveIntentRepositoryTest}).
 */
@WebFluxTest(controllers = GoLiveInternalController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class GoLiveInternalControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean GoLiveService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    // ── reachable without a JWT (mTLS is the boundary, not a bearer token) ───────────

    @Test
    void appliedAck_internalPath_isReachableWithoutJwt_casWon_appliedTrue() {
        when(service.applyAck(eq("gl-1"), eq(7L), eq("node-fp-abc123")))
                .thenReturn(Mono.just(1L));
        web.post().uri("/bff/internal/go-live/gl-1/applied-ack")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"generation\":7,\"appliedBy\":\"node-fp-abc123\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("gl-1")
                .jsonPath("$.applied").isEqualTo(true);
    }

    // ── CAS loss is a normal 200, never an HTTP error (idempotent poller contract) ───

    @Test
    void appliedAck_casLost_stillReturns200_appliedFalse() {
        when(service.applyAck(eq("gl-1"), eq(7L), eq("node-fp-abc123")))
                .thenReturn(Mono.just(0L));
        web.post().uri("/bff/internal/go-live/gl-1/applied-ack")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"generation\":7,\"appliedBy\":\"node-fp-abc123\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("gl-1")
                .jsonPath("$.applied").isEqualTo(false);
    }

    // ── request-body validation (before the service is ever called) ─────────────────

    @Test
    void appliedAck_missingGeneration_400() {
        web.post().uri("/bff/internal/go-live/gl-1/applied-ack")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"appliedBy\":\"node-fp-abc123\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.generation").exists();
        verify(service, never()).applyAck(anyString(), anyLong(), anyString());
    }

    @Test
    void appliedAck_blankAppliedBy_400() {
        web.post().uri("/bff/internal/go-live/gl-1/applied-ack")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"generation\":7,\"appliedBy\":\"\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.appliedBy").exists();
        verify(service, never()).applyAck(anyString(), anyLong(), anyString());
    }

    @Test
    void appliedAck_nonPositiveGeneration_400() {
        web.post().uri("/bff/internal/go-live/gl-1/applied-ack")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"generation\":0,\"appliedBy\":\"node-fp-abc123\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.generation").exists();
        verify(service, never()).applyAck(anyString(), anyLong(), anyString());
    }
}
