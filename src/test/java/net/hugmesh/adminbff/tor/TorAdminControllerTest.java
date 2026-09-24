package net.hugmesh.adminbff.tor;

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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.tor.TorExportModels.SignedTorExport;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The {@code /bff/admin/tor} role matrix, with the real {@link SecurityConfig} so both the
 * coarse path gate and the per-method {@code @PreAuthorize} run (hugmesh-admin-bff-api#108):
 * <ul>
 *   <li>list: SUPERADMIN and ADMIN reach it (the ADMIN redaction is the service's, pinned in
 *       {@link TorNodeServiceTest}); the ADMIN call is scoped, not superadmin; MOD/USER 403;</li>
 *   <li>set upstream and export: SUPERADMIN only; ADMIN/USER 403 and never reach the service;</li>
 *   <li>a refused upstream surfaces as 422.</li>
 * </ul>
 */
@WebFluxTest(controllers = TorAdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class TorAdminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean TorNodeService nodes;
    @MockitoBean TorExportService export;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient as(String... roles) {
        SimpleGrantedAuthority[] a = new SimpleGrantedAuthority[roles.length + 1];
        a[0] = new SimpleGrantedAuthority("ROLE_USER");
        for (int i = 0; i < roles.length; i++) a[i + 1] = new SimpleGrantedAuthority("ROLE_" + roles[i]);
        // The roles CLAIM too, not just the authorities: PrincipalDomain.of reads the claim
        // (Roles.isSuperadmin(Jwt)), exactly as a real Casdoor token carries it.
        List<String> claim = new java.util.ArrayList<>();
        for (String r : roles) claim.add(r.toLowerCase());
        return web.mutateWith(mockJwt().jwt(j -> j.claim("roles", claim)).authorities(a));
    }

    private static final String A = "a".repeat(56) + ".onion";

    private static TorNodeView view() {
        return new TorNodeView("fp-1", "edge", "default", true, A, Map.of(), true, "10.0.0.7:443", 2L,
                Instant.now(), 3L);
    }

    @Test
    void list_asSuperadmin_isAllowed_withAnUnscopedPrincipal() {
        when(nodes.list(any())).thenReturn(Flux.just(view()));
        as("SUPERADMIN").get().uri("/bff/admin/tor/nodes").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$[0].node").isEqualTo("fp-1")
                .jsonPath("$[0].primary").isEqualTo(A)
                .jsonPath("$[0].upstream").isEqualTo("10.0.0.7:443");
        verify(nodes).list(argThat(PrincipalDomain::superadmin));
    }

    @Test
    void list_asAdmin_isAllowed_withAScopedPrincipal() {
        when(nodes.list(any())).thenReturn(Flux.empty());
        as("ADMIN").get().uri("/bff/admin/tor/nodes").exchange().expectStatus().isOk();
        verify(nodes).list(argThat(s -> !s.superadmin()));
    }

    @Test
    void list_asModOrUser_isForbidden() {
        as("MOD").get().uri("/bff/admin/tor/nodes").exchange().expectStatus().isForbidden();
        as().get().uri("/bff/admin/tor/nodes").exchange().expectStatus().isForbidden();
        verify(nodes, never()).list(any());
    }

    @Test
    void setUpstream_asSuperadmin_isAllowed() {
        when(nodes.setUpstream(eq("fp-1"), eq("10.0.0.7:443"), anyString())).thenReturn(Mono.just(
                new TorNodeConfig("fp-1", true, "10.0.0.7:443", 1L, "root", Instant.now())));
        as("SUPERADMIN").put().uri("/bff/admin/tor/nodes/fp-1/upstream")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"upstream\":\"10.0.0.7:443\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.upstream").isEqualTo("10.0.0.7:443")
                .jsonPath("$.upstreamManaged").isEqualTo(true)
                .jsonPath("$.configGeneration").isEqualTo(1);
    }

    @Test
    void setUpstream_nullBody_meansTheAgentDefault() {
        when(nodes.setUpstream(eq("fp-1"), isNull(), anyString())).thenReturn(Mono.just(
                new TorNodeConfig("fp-1", true, null, 2L, "root", Instant.now())));
        as("SUPERADMIN").put().uri("/bff/admin/tor/nodes/fp-1/upstream")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"upstream\":null}")
                .exchange().expectStatus().isOk();
        verify(nodes).setUpstream(eq("fp-1"), isNull(), anyString());
    }

    @Test
    void setUpstream_refused_is422() {
        when(nodes.setUpstream(anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(ApiException.unprocessable("upstream must be one host:port token")));
        as("SUPERADMIN").put().uri("/bff/admin/tor/nodes/fp-1/upstream")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"upstream\":\"bad value\"}")
                .exchange().expectStatus().isEqualTo(422);
    }

    @Test
    void setUpstream_asAdmin_isForbidden_andNeverReachesTheService() {
        as("ADMIN").put().uri("/bff/admin/tor/nodes/fp-1/upstream")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"upstream\":\"10.0.0.7:443\"}")
                .exchange().expectStatus().isForbidden();
        verify(nodes, never()).setUpstream(any(), any(), any());
    }

    @Test
    void export_asSuperadmin_isAllowed() {
        when(export.exportNode("fp-1")).thenReturn(Mono.just(new SignedTorExport(
                new TorExportModels.TorExportBody("fp-1", 3L, true, "10.0.0.7:443", true, List.of("brandb")),
                "hash", "sig", "pub", true)));
        as("SUPERADMIN").get().uri("/bff/admin/tor/export?node=fp-1").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.body.domains[0]").isEqualTo("brandb")
                .jsonPath("$.body.upstream").isEqualTo("10.0.0.7:443")
                .jsonPath("$.signed").isEqualTo(true);
    }

    @Test
    void export_asAdminOrUser_isForbidden() {
        as("ADMIN").get().uri("/bff/admin/tor/export?node=fp-1").exchange().expectStatus().isForbidden();
        as().get().uri("/bff/admin/tor/export?node=fp-1").exchange().expectStatus().isForbidden();
        verify(export, never()).exportNode(anyString());
    }
}
