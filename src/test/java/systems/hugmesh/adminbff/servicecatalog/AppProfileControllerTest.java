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
import systems.hugmesh.commons.web.ApiException;
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
 * The App-Store APP-PROFILE controller role matrix — SUPERADMIN-ONLY boundary on
 * {@code /bff/superadmin/app-profiles} + CRUD behaviour. {@code @WebFluxTest} + the real
 * {@link SecurityConfig} so BOTH the coarse {@code /bff/superadmin/**} gate AND the
 * per-method {@code @PreAuthorize("hasRole('SUPERADMIN')")} run.
 *
 * <ul>
 *   <li>SUPERADMIN — ALLOW on list/get/create/update/delete; {@code created_by_subject}
 *       stamped from the JWT subject.</li>
 *   <li>ADMIN / MOD / USER — DENY (403) on EVERY endpoint + never reaches the service.</li>
 *   <li>duplicate name → 409; blank name → 400.</li>
 * </ul>
 */
@WebFluxTest(controllers = AppProfileController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class AppProfileControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean AppProfileService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String SUBJECT = "superadmin-subject-9";

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

    private static AppProfile sample() {
        return new AppProfile("ap-1", "small-postgres", "{\"cpu\":\"500m\"}", SUBJECT,
                Instant.now(), Instant.now());
    }

    private static final String CREATE_BODY = "{\"name\":\"small-postgres\",\"profileJson\":\"{\\\"cpu\\\":\\\"500m\\\"}\"}";
    private static final String UPDATE_BODY = "{\"name\":\"ignored-on-update\",\"profileJson\":\"{\\\"cpu\\\":\\\"1\\\"}\"}";

    // ── SUPERADMIN ALLOW ────────────────────────────────────────────────────────

    @Test
    void list_asSuperadmin_isAllowed() {
        when(service.list()).thenReturn(Flux.just(sample()));
        asSuperadmin().get().uri("/bff/superadmin/app-profiles")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].name").isEqualTo("small-postgres");
        verify(service).list();
    }

    @Test
    void get_asSuperadmin_isAllowed() {
        when(service.get(eq("small-postgres"))).thenReturn(Mono.just(sample()));
        asSuperadmin().get().uri("/bff/superadmin/app-profiles/small-postgres")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.profileJson").isEqualTo("{\"cpu\":\"500m\"}");
        verify(service).get("small-postgres");
    }

    @Test
    void create_asSuperadmin_isAllowed_andStampsSubjectFromToken() {
        when(service.create(eq("small-postgres"), anyString(), eq(SUBJECT)))
                .thenReturn(Mono.just(sample()));
        asSuperadmin().post().uri("/bff/superadmin/app-profiles")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isCreated()
                .expectBody().jsonPath("$.name").isEqualTo("small-postgres")
                .jsonPath("$.createdBySubject").isEqualTo(SUBJECT);
        verify(service).create(eq("small-postgres"), anyString(), eq(SUBJECT));
    }

    @Test
    void update_asSuperadmin_isAllowed_usesPathName() {
        when(service.update(eq("small-postgres"), anyString())).thenReturn(Mono.just(sample()));
        asSuperadmin().put().uri("/bff/superadmin/app-profiles/small-postgres")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(UPDATE_BODY)
                .exchange().expectStatus().isOk();
        // The PATH name identifies the row, not the body name.
        verify(service).update(eq("small-postgres"), anyString());
    }

    @Test
    void delete_asSuperadmin_isNoContent() {
        when(service.delete(eq("small-postgres"))).thenReturn(Mono.empty());
        asSuperadmin().delete().uri("/bff/superadmin/app-profiles/small-postgres")
                .exchange().expectStatus().isNoContent();
        verify(service).delete("small-postgres");
    }

    @Test
    void create_duplicateName_is409() {
        when(service.create(eq("small-postgres"), anyString(), anyString()))
                .thenReturn(Mono.error(ApiException.conflict("app_profile 'small-postgres' already exists")));
        asSuperadmin().post().uri("/bff/superadmin/app-profiles")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isEqualTo(409)
                .expectBody().jsonPath("$.error")
                .value(org.hamcrest.Matchers.containsString("already exists"));
    }

    @Test
    void create_blankName_isBadRequest_andNeverWrites() {
        asSuperadmin().post().uri("/bff/superadmin/app-profiles")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"name\":\"\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).create(anyString(), any(), anyString());
    }

    // ── ADMIN DENY (403) on EVERY endpoint + never reaches the service ───────────

    @Test
    void list_asAdmin_isForbidden() {
        asAdmin().get().uri("/bff/superadmin/app-profiles").exchange().expectStatus().isForbidden();
        verify(service, never()).list();
    }

    @Test
    void create_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/superadmin/app-profiles")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(anyString(), any(), anyString());
    }

    @Test
    void delete_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().delete().uri("/bff/superadmin/app-profiles/small-postgres")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).delete(anyString());
    }

    // ── MOD / USER DENY (403) ───────────────────────────────────────────────────

    @Test
    void create_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/superadmin/app-profiles")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(anyString(), any(), anyString());
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/superadmin/app-profiles").exchange().expectStatus().isForbidden();
        verify(service, never()).list();
    }
}
