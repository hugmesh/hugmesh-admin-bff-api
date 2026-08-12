package net.hugmesh.adminbff.gamesservices;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.CreateGameInstanceRequest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The instance service over real H2 repos — proves the SUPERADMIN CREATION GATE
 * (fail-closed 403 on no-offer / withdrawn / not-enabled / quota-exceeded), the success
 * path, owner==subject, and the PrincipalDomain tenant boundary on lifecycle transitions.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
// DELETEs the seeded game_server_catalog in @BeforeEach; mark dirty AFTER_CLASS so the
// shared (cached) context is re-seeded for sibling classes (see GamesCatalogServiceTest).
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class GameInstanceServiceTest {

    @Autowired DatabaseClient db;

    private GameInstanceRepository instances;
    private GameServerDomainOfferRepository offers;
    private GameServerCatalogRepository catalog;
    private GameInstanceService service;

    private static final String PINNED = "ghcr.io/org/g@sha256:"
            + "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    @BeforeEach
    void setup() {
        db.sql("DELETE FROM game_instance").fetch().rowsUpdated().block();
        db.sql("DELETE FROM game_server_domain_offer").fetch().rowsUpdated().block();
        db.sql("DELETE FROM game_server_catalog").fetch().rowsUpdated().block();
        instances = new GameInstanceRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.gamesservices.GameInstanceR2dbcRepository.class));
        offers = new GameServerDomainOfferRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.gamesservices.GameServerDomainOfferR2dbcRepository.class));
        catalog = new GameServerCatalogRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.gamesservices.GameServerCatalogR2dbcRepository.class));
        service = new GameInstanceService(instances, offers, catalog);
        // A curated, enabled catalog entry (the slug must exist + be enabled to create).
        catalog.insert(new GameServerCatalogEntry(null, "minetest", "Luanti", PINNED,
                "LGPL-2.1-or-later", "udp", 30000, null, null, true, null, "seed", null), "super").block();
    }

    private static PrincipalDomain brandx() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("alice").issuer("https://idp.brandx.example")
                .claim("roles", List.of("admin")).build();
        Authentication auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private void offer(String domain, String slug, boolean offered, boolean enabled, int max) {
        offers.insert(new GameServerDomainOffer(null, domain, slug, offered, enabled, max, null, null, null), "super").block();
    }

    private static CreateGameInstanceRequest req(String slug, String name) {
        return new CreateGameInstanceRequest(slug, name, null);
    }

    private static int status(Throwable e) {
        return ((ApiException) e).status().value();
    }

    // ── CREATION GATE — fail-closed 403 ──────────────────────────────────────────

    @Test
    void create_noOffer_is403() {
        StepVerifier.create(service.create(req("minetest", "w"), "alice", brandx()))
                .expectErrorSatisfies(e -> assertThat(status(e)).isEqualTo(403))
                .verify();
    }

    @Test
    void create_offerWithdrawn_is403() {
        offer("brandx", "minetest", false, true, 5);   // offered_by_superadmin = false
        StepVerifier.create(service.create(req("minetest", "w"), "alice", brandx()))
                .expectErrorSatisfies(e -> assertThat(status(e)).isEqualTo(403))
                .verify();
    }

    @Test
    void create_notEnabledByAdmin_is403() {
        offer("brandx", "minetest", true, false, 5);   // enabled_by_admin = false
        StepVerifier.create(service.create(req("minetest", "w"), "alice", brandx()))
                .expectErrorSatisfies(e -> assertThat(status(e)).isEqualTo(403))
                .verify();
    }

    @Test
    void create_quotaExceeded_is403() {
        offer("brandx", "minetest", true, true, 1);    // quota = 1
        service.create(req("minetest", "first"), "alice", brandx()).block();
        // The second create exceeds the quota.
        StepVerifier.create(service.create(req("minetest", "second"), "alice", brandx()))
                .expectErrorSatisfies(e -> assertThat(status(e)).isEqualTo(403))
                .verify();
    }

    @Test
    void create_offeredEnabledWithHeadroom_succeeds_ownerIsSubject() {
        offer("brandx", "minetest", true, true, 3);
        GameInstance i = service.create(req("minetest", "world1"), "alice", brandx()).block();
        assertThat(i).isNotNull();
        assertThat(i.domain()).isEqualTo("brandx");
        assertThat(i.state()).isEqualTo("pending");
        assertThat(i.ownerSubject()).isEqualTo("alice");   // owner == subject
    }

    @Test
    void create_softDisabledCatalogEntry_is403() {
        // Disable the catalog entry; an offer alone is not enough.
        catalog.update(new GameServerCatalogEntry(null, "minetest", "Luanti", PINNED,
                "LGPL-2.1-or-later", "udp", 30000, null, null, false, null, null, null)).block();
        offer("brandx", "minetest", true, true, 5);
        StepVerifier.create(service.create(req("minetest", "w"), "alice", brandx()))
                .expectErrorSatisfies(e -> assertThat(status(e)).isEqualTo(403))
                .verify();
    }

    @Test
    void create_duplicateName_is409() {
        offer("brandx", "minetest", true, true, 5);
        service.create(req("minetest", "dup"), "alice", brandx()).block();
        StepVerifier.create(service.create(req("minetest", "dup"), "alice", brandx()))
                .expectErrorSatisfies(e -> assertThat(status(e)).isEqualTo(409))
                .verify();
    }

    @Test
    void create_unscopedCaller_is403_failClosed() {
        // A NO_DOMAIN scope can satisfy no offer.
        offer("brandx", "minetest", true, true, 5);
        PrincipalDomain unscoped = PrincipalDomain.of(null, REGISTRY);
        StepVerifier.create(service.create(req("minetest", "w"), "ghost", unscoped))
                .expectErrorSatisfies(e -> assertThat(status(e)).isEqualTo(403))
                .verify();
    }

    // ── lifecycle + scope boundary ────────────────────────────────────────────────

    @Test
    void terminate_thenCreateSameName_succeeds_quotaFreed() {
        offer("brandx", "minetest", true, true, 1);
        GameInstance first = service.create(req("minetest", "w"), "alice", brandx()).block();
        service.terminate(first.id(), brandx()).block();
        // Terminated frees the quota slot + the partial-unique name.
        GameInstance again = service.create(req("minetest", "w"), "alice", brandx()).block();
        assertThat(again.state()).isEqualTo("pending");
        assertThat(again.id()).isNotEqualTo(first.id());
    }

    @Test
    void transition_otherBrand_is404_invisible() {
        offer("brandy", "minetest", true, true, 5);
        // Create a brandy instance via a brandy scope.
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("bob").issuer("https://idp.brandy.example").claim("roles", List.of("admin")).build();
        Authentication yauth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        PrincipalDomain brandy = PrincipalDomain.of(yauth, REGISTRY);
        GameInstance y = service.create(req("minetest", "yw"), "bob", brandy).block();

        // brand-X admin cannot resolve/terminate the brand-Y instance.
        StepVerifier.create(service.terminate(y.id(), brandx()))
                .expectErrorSatisfies(e -> assertThat(status(e)).isEqualTo(404))
                .verify();
    }
}
