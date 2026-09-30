package net.hugmesh.adminbff.tor;

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
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * {@code POST /bff/internal/tor/onions} — the node's onion report rides the SAME channel as the
 * device-enrollment self-report: no Casdoor JWT (the node presents the in-cluster
 * {@code X-Internal-Token}; this slice is the UNARMED dev/test parity branch, the armed role
 * matrix is {@code InternalSurfaceRoleMatrixTest}); a minimal ACK; a malformed body is a 400
 * and a value the agent could not have exported is a 422, neither reaching the store
 * (hugmesh-admin-bff-api#108).
 */
@WebFluxTest(controllers = TorInternalController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class TorInternalControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean TorNodeService nodes;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    static final String A = "a".repeat(56) + ".onion";
    static final String B = "b".repeat(56) + ".onion";

    @Test
    void report_noJwt_isAccepted_minimalAck() {
        when(nodes.report(eq("fp-1"), eq(A), eq(Map.of("brandb", B)))).thenReturn(Mono.just(
                new TorNodeReport("fp-1", A, Map.of("brandb", B), Instant.now(), Instant.now(), 4L)));
        web.post().uri("/bff/internal/tor/onions").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"machineKeyFp\":\"fp-1\",\"primary\":\"" + A + "\",\"domains\":{\"brandb\":\"" + B + "\"}}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.accepted").isEqualTo(true)
                .jsonPath("$.reportCount").isEqualTo(4)
                .jsonPath("$.primary").doesNotExist()
                .jsonPath("$.domains").doesNotExist();
    }

    @Test
    void report_beforeMint_primaryAndDomainsMayBeAbsent() {
        when(nodes.report(eq("fp-1"), isNull(), isNull())).thenReturn(Mono.just(
                new TorNodeReport("fp-1", null, Map.of(), Instant.now(), Instant.now(), 1L)));
        web.post().uri("/bff/internal/tor/onions").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"machineKeyFp\":\"fp-1\"}")
                .exchange().expectStatus().isOk();
        verify(nodes).report(eq("fp-1"), isNull(), isNull());
    }

    @Test
    void report_blankFp_is400_andNeverStores() {
        web.post().uri("/bff/internal/tor/onions").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"machineKeyFp\":\"\",\"primary\":\"" + A + "\"}")
                .exchange().expectStatus().isBadRequest();
        verify(nodes, never()).report(anyString(), any(), any());
    }

    @Test
    void report_overlongPrimary_is400_andNeverStores() {
        web.post().uri("/bff/internal/tor/onions").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"machineKeyFp\":\"fp-1\",\"primary\":\"" + A + "x\"}")
                .exchange().expectStatus().isBadRequest();
        verify(nodes, never()).report(anyString(), any(), any());
    }

    @Test
    void report_valueRefusedByTheService_is422() {
        when(nodes.report(anyString(), any(), any()))
                .thenReturn(Mono.error(ApiException.unprocessable("primary must be a Tor v3 onion hostname")));
        web.post().uri("/bff/internal/tor/onions").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"machineKeyFp\":\"fp-1\",\"primary\":\"nope.onion\"}")
                .exchange().expectStatus().isEqualTo(422);
    }
}
