package net.hugmesh.adminbff.matrixadmin;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import java.time.Instant;
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
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;

/**
 * The HTTP surface of the ADMIN Matrix deactivate through the REAL {@link SecurityConfig} chain
 * and REAL {@code @PreAuthorize} method security: ADMIN and SUPERADMIN (via the role hierarchy)
 * reach it; MOD, USER and anonymous callers never reach the service. Plus the status mapping of
 * each service result.
 */
@WebFluxTest(controllers = MatrixAdminDeactivateController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class MatrixAdminDeactivateControllerTest {

    private static final String BASE = "/bff/admin/matrix/deactivations";

    @Autowired ApplicationContext context;
    @MockitoBean MatrixDeactivateService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    WebTestClient web;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient as(String subject, String... roles) {
        SimpleGrantedAuthority[] auths = new SimpleGrantedAuthority[roles.length];
        for (int i = 0; i < roles.length; i++) {
            auths[i] = new SimpleGrantedAuthority("ROLE_" + roles[i]);
        }
        return web.mutateWith(mockJwt().jwt(j -> j.subject(subject)).authorities(auths));
    }

    private static MatrixDeactivateService.Proposal proposal() {
        return new MatrixDeactivateService.Proposal("p-1", "@victim:hugmesh.net", "tok",
                Instant.parse("2026-09-23T12:02:00Z"), 120);
    }

    private WebTestClient.ResponseSpec propose(WebTestClient c) {
        return c.post().uri(BASE + "/propose").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"mxid\":\"@victim:hugmesh.net\"}").exchange();
    }

    private WebTestClient.ResponseSpec confirm(WebTestClient c, String token) {
        return c.post().uri(BASE + "/confirm").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"mxid\":\"@victim:hugmesh.net\",\"token\":\"" + token + "\"}").exchange();
    }

    // ── who may call it ──────────────────────────────────────────────────────────────

    @Test
    void admin_proposes_boundToTheirOwnJwtSubject() {
        when(service.propose("admin-sub", "@victim:hugmesh.net")).thenReturn(Mono.just(proposal()));

        propose(as("admin-sub", "USER", "ADMIN")).expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.token").isEqualTo("tok")
                .jsonPath("$.ttlSeconds").isEqualTo(120)
                .jsonPath("$.oneWay").isEqualTo(true);
        verify(service).propose("admin-sub", "@victim:hugmesh.net");
    }

    @Test
    void superadmin_passesHasRoleAdmin_throughTheRoleHierarchy() {
        when(service.propose("root-sub", "@victim:hugmesh.net")).thenReturn(Mono.just(proposal()));

        propose(as("root-sub", "SUPERADMIN")).expectStatus().isCreated();
    }

    @Test
    void mod_isForbidden_andNeverReachesTheService() {
        propose(as("mod-sub", "USER", "MOD")).expectStatus().isForbidden();
        confirm(as("mod-sub", "USER", "MOD"), "tok").expectStatus().isForbidden();
        verify(service, never()).propose(anyString(), anyString());
        verify(service, never()).confirm(anyString(), anyString(), any());
    }

    @Test
    void plainUser_isForbidden() {
        propose(as("user-sub", "USER")).expectStatus().isForbidden();
        verify(service, never()).propose(anyString(), anyString());
    }

    @Test
    void anonymous_isUnauthorized() {
        web.post().uri(BASE + "/propose").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"mxid\":\"victim\"}").exchange().expectStatus().isUnauthorized();
        verify(service, never()).propose(anyString(), anyString());
    }

    // ── what each result maps to ─────────────────────────────────────────────────────

    @Test
    void confirm_posted_is202() {
        when(service.confirm("admin-sub", "@victim:hugmesh.net", "tok")).thenReturn(Mono.just(
                new MatrixDeactivateService.Confirmation("p-1", "@victim:hugmesh.net",
                        MatrixAdminOutcome.posted("$e"))));

        confirm(as("admin-sub", "ADMIN"), "tok").expectStatus().isAccepted()
                .expectBody().jsonPath("$.outcome").isEqualTo("posted:$e");
    }

    @Test
    void confirm_degraded_is502() {
        when(service.confirm(eq("admin-sub"), anyString(), any())).thenReturn(Mono.just(
                new MatrixDeactivateService.Confirmation("p-1", "@victim:hugmesh.net",
                        MatrixAdminOutcome.degraded("no-admin-token"))));

        confirm(as("admin-sub", "ADMIN"), "tok").expectStatus().isEqualTo(502)
                .expectBody().jsonPath("$.outcome").isEqualTo("degraded:no-admin-token");
    }

    @Test
    void confirm_refused_is403_withTheReason() {
        for (MatrixDeactivateService.Refusal r : MatrixDeactivateService.Refusal.values()) {
            when(service.confirm(eq("admin-sub"), anyString(), any()))
                    .thenReturn(Mono.error(refused(r)));
            confirm(as("admin-sub", "ADMIN"), "tok").expectStatus().isForbidden()
                    .expectBody()
                    .jsonPath("$.refused").isEqualTo(true)
                    .jsonPath("$.reason").isEqualTo(r.code());
        }
    }

    @Test
    void dark_is503() {
        when(service.propose(anyString(), anyString())).thenReturn(Mono.error(dark()));

        propose(as("admin-sub", "ADMIN")).expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.dark").isEqualTo(true);
    }

    @Test
    void aBlankMxid_isABadRequest_beforeTheService() {
        as("admin-sub", "ADMIN").post().uri(BASE + "/propose").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"mxid\":\"\"}").exchange().expectStatus().isBadRequest();
        verify(service, never()).propose(anyString(), anyString());
    }

    /**
     * The per-method gate is the decision's own wording (hasRole('ADMIN')). MOD is ALSO kept out
     * by the /bff/admin/** path matcher, so the HTTP tests above cannot tell whether the method
     * gate exists; this pins it directly, so moving the controller off /bff/admin/** (or widening
     * the path table) cannot silently open the one-way door to another role.
     */
    @Test
    void everyMappingMethod_isGatedHasRoleAdmin() {
        int mapped = 0;
        for (java.lang.reflect.Method m : MatrixAdminDeactivateController.class.getDeclaredMethods()) {
            if (m.isAnnotationPresent(org.springframework.web.bind.annotation.PostMapping.class)
                    || m.isAnnotationPresent(org.springframework.web.bind.annotation.GetMapping.class)
                    || m.isAnnotationPresent(org.springframework.web.bind.annotation.RequestMapping.class)) {
                mapped++;
                org.springframework.security.access.prepost.PreAuthorize pa =
                        m.getAnnotation(org.springframework.security.access.prepost.PreAuthorize.class);
                org.assertj.core.api.Assertions.assertThat(pa).as(m.getName()).isNotNull();
                org.assertj.core.api.Assertions.assertThat(pa.value()).as(m.getName())
                        .isEqualTo("hasRole('ADMIN')");
            }
        }
        org.assertj.core.api.Assertions.assertThat(mapped).isEqualTo(2);
    }

    private static MatrixDeactivateService.RefusedException refused(MatrixDeactivateService.Refusal r) {
        return new MatrixDeactivateService.RefusedException(r);
    }

    private static MatrixDeactivateService.DarkException dark() {
        return new MatrixDeactivateService.DarkException();
    }
}
