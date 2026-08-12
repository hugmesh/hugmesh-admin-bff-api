package net.hugmesh.adminbff.gamesservices;
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
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.adminbff.web.dto.GameCatalogEntryRequest;
import net.hugmesh.adminbff.web.dto.GameDomainOfferRequest;

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
 * The games-services SUPERADMIN catalog control-plane role matrix — the acceptance bar for
 * the SUPERADMIN-ONLY boundary on {@code /bff/superadmin/games-services/**}. Mirrors
 * {@code DomainRegistryControllerTest}: {@code @WebFluxTest} + the real {@link SecurityConfig}
 * so BOTH the coarse {@code /bff/superadmin/**} path gate AND the per-method
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} run.
 *
 * <ul>
 *   <li>SUPERADMIN — ALLOW on catalog + offer CRUD; created_by stamped from the JWT.</li>
 *   <li>ADMIN / MOD / USER — 403 on EVERY endpoint + never reach the service.</li>
 *   <li>tag-only imageRef -&gt; 400 (digest-pin gate); duplicate slug/offer -&gt; 409.</li>
 * </ul>
 */
@WebFluxTest(controllers = GamesCatalogSuperadminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class GamesCatalogSuperadminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean GamesCatalogService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String SUBJECT = "superadmin-subject-7";

    private static final String SHA64 =
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private static final String PINNED = "ghcr.io/org/minetest@sha256:" + SHA64;

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

    private static GameServerCatalogEntry sampleEntry() {
        return new GameServerCatalogEntry("gsc-minetest", "minetest", "Luanti", PINNED,
                "LGPL-2.1-or-later", "udp", 30000, null, "voxel sandbox", true,
                Instant.now(), SUBJECT, Instant.now());
    }

    private static GameServerDomainOffer sampleOffer() {
        return new GameServerDomainOffer("off-1", "acme.test", "minetest", true, false, 3,
                Instant.now(), SUBJECT, Instant.now());
    }

    private static final String CATALOG_BODY = "{"
            + "\"slug\":\"minetest\",\"displayName\":\"Luanti\",\"imageRef\":\"" + PINNED + "\","
            + "\"licenseSpdx\":\"LGPL-2.1-or-later\",\"protocol\":\"udp\",\"containerPort\":30000}";

    private static final String OFFER_BODY = "{\"slug\":\"minetest\",\"maxInstances\":3}";

    // ── SUPERADMIN ALLOW ────────────────────────────────────────────────────────

    @Test
    void listCatalog_asSuperadmin_isAllowed() {
        when(service.listCatalog()).thenReturn(Flux.just(sampleEntry()));
        asSuperadmin().get().uri("/bff/superadmin/games-services/catalog")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].slug").isEqualTo("minetest");
        verify(service).listCatalog();
    }

    @Test
    void createCatalog_asSuperadmin_isAllowed_andStampsSubject() {
        when(service.createCatalog(any(GameCatalogEntryRequest.class), eq(SUBJECT)))
                .thenReturn(Mono.just(sampleEntry()));
        asSuperadmin().post().uri("/bff/superadmin/games-services/catalog")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CATALOG_BODY)
                .exchange().expectStatus().isCreated()
                .expectBody().jsonPath("$.slug").isEqualTo("minetest")
                .jsonPath("$.createdBySubject").isEqualTo(SUBJECT);
        verify(service).createCatalog(any(GameCatalogEntryRequest.class), eq(SUBJECT));
    }

    @Test
    void createCatalog_tagOnlyImageRef_is400_fromServiceGate() {
        when(service.createCatalog(any(GameCatalogEntryRequest.class), anyString()))
                .thenReturn(Mono.error(ApiException.badRequest(
                        "imageRef must be digest-pinned (repo@sha256:<64 hex>); tag-only "
                        + "references are rejected (arbitrary-container exec containment)")));
        asSuperadmin().post().uri("/bff/superadmin/games-services/catalog")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"slug\":\"x\",\"displayName\":\"X\",\"imageRef\":\"ghcr.io/x:latest\","
                        + "\"licenseSpdx\":\"MIT\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("digest-pinned"));
    }

    @Test
    void createCatalog_duplicateSlug_is409() {
        when(service.createCatalog(any(GameCatalogEntryRequest.class), anyString()))
                .thenReturn(Mono.error(ApiException.conflict("catalog entry 'minetest' already exists")));
        asSuperadmin().post().uri("/bff/superadmin/games-services/catalog")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CATALOG_BODY)
                .exchange().expectStatus().isEqualTo(409);
    }

    @Test
    void updateCatalog_asSuperadmin_isAllowed() {
        when(service.updateCatalog(eq("minetest"), any())).thenReturn(Mono.just(sampleEntry()));
        asSuperadmin().put().uri("/bff/superadmin/games-services/catalog/minetest")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"enabled\":false}")
                .exchange().expectStatus().isOk();
        verify(service).updateCatalog(eq("minetest"), any());
    }

    @Test
    void createOffer_asSuperadmin_isAllowed_theCreationGate() {
        when(service.createOffer(eq("acme.test"), any(GameDomainOfferRequest.class), eq(SUBJECT)))
                .thenReturn(Mono.just(sampleOffer()));
        asSuperadmin().post().uri("/bff/superadmin/games-services/offers/acme.test")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isCreated()
                .expectBody().jsonPath("$.slug").isEqualTo("minetest")
                .jsonPath("$.offeredBySuperadmin").isEqualTo(true)
                .jsonPath("$.maxInstances").isEqualTo(3);
        verify(service).createOffer(eq("acme.test"), any(GameDomainOfferRequest.class), eq(SUBJECT));
    }

    @Test
    void createOffer_unknownSlug_is404() {
        when(service.createOffer(anyString(), any(), anyString()))
                .thenReturn(Mono.error(ApiException.notFound(
                        "no catalog entry for slug 'ghost' — curate it before offering")));
        asSuperadmin().post().uri("/bff/superadmin/games-services/offers/acme.test")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"slug\":\"ghost\"}")
                .exchange().expectStatus().isNotFound();
    }

    @Test
    void updateOffer_asSuperadmin_canWithdraw() {
        GameServerDomainOffer withdrawn = new GameServerDomainOffer("off-1", "acme.test",
                "minetest", false, false, 3, Instant.now(), SUBJECT, Instant.now());
        when(service.updateOffer(eq("acme.test"), eq("minetest"), any()))
                .thenReturn(Mono.just(withdrawn));
        asSuperadmin().put().uri("/bff/superadmin/games-services/offers/acme.test/minetest")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"offeredBySuperadmin\":false}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.offeredBySuperadmin").isEqualTo(false);
    }

    // ── ADMIN DENY (403) on EVERY endpoint + never reaches the service ───────────

    @Test
    void listCatalog_asAdmin_isForbidden() {
        asAdmin().get().uri("/bff/superadmin/games-services/catalog")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).listCatalog();
    }

    @Test
    void createCatalog_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/superadmin/games-services/catalog")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CATALOG_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).createCatalog(any(), anyString());
    }

    @Test
    void createOffer_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/superadmin/games-services/offers/acme.test")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).createOffer(anyString(), any(), anyString());
    }

    @Test
    void updateOffer_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().put().uri("/bff/superadmin/games-services/offers/acme.test/minetest")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"maxInstances\":9}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).updateOffer(anyString(), anyString(), any());
    }

    // ── MOD DENY ─────────────────────────────────────────────────────────────────

    @Test
    void listCatalog_asMod_isForbidden() {
        asMod().get().uri("/bff/superadmin/games-services/catalog")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).listCatalog();
    }

    @Test
    void createOffer_asMod_isForbidden() {
        asMod().post().uri("/bff/superadmin/games-services/offers/acme.test")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).createOffer(anyString(), any(), anyString());
    }

    // ── USER DENY ──────────────────────────────────────────────────────────────────

    @Test
    void listCatalog_asUser_isForbidden() {
        asUser().get().uri("/bff/superadmin/games-services/catalog")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void createCatalog_asUser_isForbidden_andNeverWrites() {
        asUser().post().uri("/bff/superadmin/games-services/catalog")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CATALOG_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).createCatalog(any(), anyString());
    }
}
