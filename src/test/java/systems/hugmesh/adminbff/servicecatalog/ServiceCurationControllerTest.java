package systems.hugmesh.adminbff.servicecatalog;
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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The App-Store CURATION controller role matrix — the acceptance bar for the SUPERADMIN-ONLY
 * boundary on {@code /bff/superadmin/service-store}. Mirrors {@code DomainRegistryControllerTest}:
 * {@code @WebFluxTest} + the real {@link SecurityConfig} so BOTH the coarse path gate
 * ({@code /bff/superadmin/** = hasRole SUPERADMIN}) AND the per-method
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} run.
 *
 * <ul>
 *   <li>SUPERADMIN — ALLOW on list / offer / withdraw; {@code curated_by_subject} stamped
 *       from the JWT subject (never the body).</li>
 *   <li>ADMIN — DENY (403) on EVERY endpoint (passes the coarse {@code /bff/admin} gate but
 *       NOT the SUPERADMIN-only {@code /bff/superadmin} gate) + never reaches the service.</li>
 *   <li>MOD / USER — DENY (403) on EVERY endpoint + never reaches the service.</li>
 * </ul>
 */
@WebFluxTest(controllers = ServiceCurationController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class ServiceCurationControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ServiceCurationService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String SUBJECT = "superadmin-subject-7";

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(SUBJECT))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static ServiceCuration sample(String domain, String key) {
        return new ServiceCuration("cur-1", domain, key, ServiceCuration.STATE_OFFERED,
                SUBJECT, Instant.now(), Instant.now());
    }

    private static final String OFFER_BODY = "{\"serviceKey\":\"owncast\"}";

    // ── SUPERADMIN ALLOW ────────────────────────────────────────────────────────

    @Test
    void list_asSuperadmin_isAllowed() {
        when(service.listForDomain(eq("acme.test"))).thenReturn(Flux.just(sample("acme.test", "owncast")));
        asSuperadmin().get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].serviceKey").isEqualTo("owncast");
        verify(service).listForDomain("acme.test");
    }

    @Test
    void offer_asSuperadmin_isAllowed_andStampsSubjectFromToken() {
        when(service.offer(eq("acme.test"), eq("owncast"), eq(SUBJECT)))
                .thenReturn(Mono.just(sample("acme.test", "owncast")));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.serviceKey").isEqualTo("owncast")
                .jsonPath("$.state").isEqualTo("offered");
        // domain from the PATH, subject from the TOKEN — never the body.
        verify(service).offer("acme.test", "owncast", SUBJECT);
    }

    @Test
    void withdraw_asSuperadmin_isAllowed() {
        ServiceCuration withdrawn = new ServiceCuration("cur-1", "acme.test", "owncast",
                ServiceCuration.STATE_WITHDRAWN, SUBJECT, Instant.now(), Instant.now());
        when(service.withdraw(eq("acme.test"), eq("owncast"), eq(SUBJECT)))
                .thenReturn(Mono.just(withdrawn));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/withdraw")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.state").isEqualTo("withdrawn");
        verify(service).withdraw("acme.test", "owncast", SUBJECT);
    }

    @Test
    void offer_blankServiceKey_isBadRequest_andNeverWrites() {
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"serviceKey\":\"\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).offer(anyString(), anyString(), anyString());
    }

    // ── ADMIN DENY (403) on EVERY endpoint + never reaches the service ───────────

    @Test
    void list_asAdmin_isForbidden() {
        asAdmin().get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).listForDomain(anyString());
    }

    @Test
    void offer_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).offer(anyString(), anyString(), anyString());
    }

    @Test
    void withdraw_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/superadmin/service-store/acme.test/withdraw")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).withdraw(anyString(), anyString(), anyString());
    }

    // ── MOD DENY (403) ──────────────────────────────────────────────────────────

    @Test
    void offer_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).offer(anyString(), anyString(), anyString());
    }

    @Test
    void list_asMod_isForbidden() {
        asMod().get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isForbidden();
    }

    // ── USER DENY (403) ─────────────────────────────────────────────────────────

    @Test
    void offer_asUser_isForbidden_andNeverWrites() {
        asUser().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).offer(anyString(), anyString(), anyString());
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isForbidden();
    }
}
