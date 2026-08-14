package net.hugmesh.adminbff.notification;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Role matrix + tenancy for the feature/infra notification triggers (Notifications PR7).
 *
 * <ul>
 *   <li>ADMIN + SUPERADMIN — ALLOW.</li>
 *   <li>MOD / USER — DENY (403) + never reach the service.</li>
 *   <li>PER-DOMAIN — the service is called with the domain resolved from the validated JWT
 *       (single-issuer test → "default"), NEVER from the body (the body has no domain).</li>
 * </ul>
 */
@WebFluxTest(controllers = FeatureNotificationController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class FeatureNotificationControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean FeatureNotificationService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    // The configured single-issuer (application.yml issuer-uri); DomainRegistry maps it to
    // "default". The JWT MUST carry it or PrincipalDomain fails closed to NO_DOMAIN (a real,
    // tested behaviour — see unknownIssuer_failsClosed below).
    private static final String ISSUER = "https://id.hugmesh.net";

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER)).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER)).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER)).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer(ISSUER))
                .authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private WebTestClient asAdminUnknownIssuer() {
        return web.mutateWith(mockJwt().jwt(j -> j.issuer("https://evil.example.org")).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private static final String BODY =
            "{\"recipientSubject\":\"subject-alice\",\"eventKey\":\"k1\",\"reason\":\"the wiki is now available\"}";

    // ── ADMIN ALLOW + domain from JWT (default), not the body ────────────────
    @Test
    void featureAvailability_asAdmin_isAllowed_andUsesJwtDomain() {
        when(service.emit(eq(FeatureNotificationService.Kind.FEATURE_AVAILABILITY),
                eq("default"), eq("subject-alice"), eq("k1"), any()))
                .thenReturn(Mono.just(true));
        asAdmin().post().uri("/bff/admin/notifications/feature-availability")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.domain").isEqualTo("default")        // from the validated JWT
                .jsonPath("$.category").isEqualTo("feature-availability")
                .jsonPath("$.emitted").isEqualTo(true);
        verify(service).emit(eq(FeatureNotificationService.Kind.FEATURE_AVAILABILITY),
                eq("default"), eq("subject-alice"), eq("k1"), any());
    }

    @Test
    void infraImpacting_asSuperadmin_isAllowed() {
        when(service.emit(eq(FeatureNotificationService.Kind.INFRA_IMPACTING),
                eq("default"), eq("subject-alice"), eq("k1"), any()))
                .thenReturn(Mono.just(true));
        asSuperadmin().post().uri("/bff/admin/notifications/infra-impacting")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.category").isEqualTo("infra-impacting");
    }

    // ── MOD / USER DENY (403) + never reach the service ──────────────────────
    @Test
    void featureAvailability_asMod_isForbidden_andNeverEmits() {
        asMod().post().uri("/bff/admin/notifications/feature-availability")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).emit(any(), any(), any(), any(), any());
    }

    @Test
    void infraImpacting_asUser_isForbidden_andNeverEmits() {
        asUser().post().uri("/bff/admin/notifications/infra-impacting")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).emit(any(), any(), any(), any(), any());
    }

    // ── PER-DOMAIN ISOLATION (fail-closed): an UNKNOWN issuer never emits ────
    @Test
    void unknownIssuer_failsClosed_400_andNeverEmits() {
        // A token whose validated issuer is not in the registry resolves to NO_DOMAIN —
        // the controller rejects (400) rather than silently emitting to a default/other
        // brand. (The resource server would already 401 such a token in prod; this is the
        // in-controller defence-in-depth.)
        asAdminUnknownIssuer().post().uri("/bff/admin/notifications/feature-availability")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).emit(any(), any(), any(), any(), any());
    }

    // ── validation: blank recipient/eventKey → 400 before emit ───────────────
    @Test
    void blankRecipient_isBadRequest_andNeverEmits() {
        asAdmin().post().uri("/bff/admin/notifications/feature-availability")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"recipientSubject\":\"\",\"eventKey\":\"k1\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).emit(any(), any(), any(), any(), any());
    }
}
