package net.hugmesh.adminbff.gamesservices;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The game_server_domain_offer R2DBC repository over a Liquibase-applied H2 (PG-compat) —
 * proves the 090 offer table applies (UNIQUE (domain,slug) + quota CHECK) and, crucially,
 * the PER-DOMAIN SCOPE ISOLATION: a scoped admin sees only their brand's offers; SUPERADMIN
 * sees every brand's. Mirrors {@code AccessSuspensionDomainScopeTest}'s JWT/scope mocking.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class GameServerDomainOfferRepositoryTest {

    @Autowired DatabaseClient db;

    /** The H2 mem store persists across methods in one test class (DB_CLOSE_DELAY=-1),
     *  so clear the offer table before each test for isolation. */
    @BeforeEach
    void clear() {
        db.sql("DELETE FROM game_server_domain_offer").fetch().rowsUpdated().block();
    }

    private GameServerDomainOfferRepository repo() {
        return new GameServerDomainOfferRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.gamesservices.GameServerDomainOfferR2dbcRepository.class));
    }

    // Multi-brand registry: two distinct issuers -> two distinct domains.
    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private static PrincipalDomain admin(String issuer) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(issuer).claim("roles", List.of("admin")).build();
        Authentication auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static PrincipalDomain superadmin() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer("https://idp.brandx.example")
                .claim("roles", List.of("superadmin")).build();
        Authentication auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static GameServerDomainOffer draft(String domain, String slug) {
        return new GameServerDomainOffer(null, domain, slug, true, false, 3, null, null, null);
    }

    @Test
    void insert_thenFind_roundTrips() {
        GameServerDomainOfferRepository repo = repo();
        GameServerDomainOffer saved = repo.insert(draft("brandx", "minetest"), "super@infra").block();
        assertThat(saved).isNotNull();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.offeredBySuperadmin()).isTrue();
        assertThat(saved.maxInstances()).isEqualTo(3);

        StepVerifier.create(repo.find("brandx", "minetest"))
                .assertNext(o -> {
                    assertThat(o.slug()).isEqualTo("minetest");
                    assertThat(o.createdBySubject()).isEqualTo("super@infra");
                })
                .verifyComplete();
    }

    @Test
    void uniqueDomainSlug_rejectsDuplicate() {
        GameServerDomainOfferRepository repo = repo();
        repo.insert(draft("brandx", "veloren"), "super@infra").block();
        StepVerifier.create(repo.insert(draft("brandx", "veloren"), "super@infra"))
                .expectError()
                .verify();
    }

    // ── CROSS-DOMAIN ISOLATION (ALLOW own / DENY other) ──────────────────────────

    @Test
    void scopedAdmin_findAll_seesOnlyOwnBrandOffers() {
        GameServerDomainOfferRepository repo = repo();
        repo.insert(draft("brandx", "xonotic"), "super@infra").block();
        repo.insert(draft("brandy", "openarena"), "super@infra").block();

        var x = repo.findAll(admin("https://idp.brandx.example")).collectList().block();
        assertThat(x).extracting(GameServerDomainOffer::domain).containsOnly("brandx");
        assertThat(x).extracting(GameServerDomainOffer::slug).containsExactly("xonotic");

        var y = repo.findAll(admin("https://idp.brandy.example")).collectList().block();
        assertThat(y).extracting(GameServerDomainOffer::domain).containsOnly("brandy");
    }

    @Test
    void scopedAdmin_find_cannotResolveOtherBrandOffer() {
        GameServerDomainOfferRepository repo = repo();
        repo.insert(draft("brandy", "teeworlds"), "super@infra").block();

        // brand-X admin asking for a brand-Y offer (even by its real domain) resolves nothing.
        StepVerifier.create(repo.find("brandy", "teeworlds", admin("https://idp.brandx.example")))
                .verifyComplete();
        // But the SUPERADMIN sees it.
        StepVerifier.create(repo.find("brandy", "teeworlds", superadmin()))
                .assertNext(o -> assertThat(o.domain()).isEqualTo("brandy"))
                .verifyComplete();
    }

    @Test
    void superadmin_findAll_seesEveryBrandOffer() {
        GameServerDomainOfferRepository repo = repo();
        repo.insert(draft("brandx", "mindustry"), "super@infra").block();
        repo.insert(draft("brandy", "zeroad"), "super@infra").block();

        var all = repo.findAll(superadmin()).collectList().block();
        assertThat(all).extracting(GameServerDomainOffer::domain).contains("brandx", "brandy");
    }

    @Test
    void update_flipsFlagsAndQuota_butNotIdentity() {
        GameServerDomainOfferRepository repo = repo();
        GameServerDomainOffer original = repo.insert(draft("brandx", "supertuxkart"), "super@infra").block();

        GameServerDomainOffer merged = new GameServerDomainOffer(original.id(), "brandx",
                "supertuxkart", true, true, 5, original.createdAt(),
                original.createdBySubject(), original.updatedAt());
        GameServerDomainOffer updated = repo.update(merged).block();

        assertThat(updated).isNotNull();
        assertThat(updated.enabledByAdmin()).isTrue();
        assertThat(updated.maxInstances()).isEqualTo(5);
        assertThat(updated.id()).isEqualTo(original.id());
    }
}
