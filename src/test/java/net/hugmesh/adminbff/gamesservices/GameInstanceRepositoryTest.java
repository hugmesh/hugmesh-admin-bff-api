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
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The game_instance R2DBC repository over a Liquibase-applied H2 (PG-compat) — proves the
 * 091 changelog applies (table + CHECKs) and the desired-state idiom round-trips: insert
 * pending, CAS state transitions (single-winner), dueForExpiry scan, per-domain active
 * working set, and the PrincipalDomain read isolation.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class GameInstanceRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM game_instance").fetch().rowsUpdated().block();
    }

    private GameInstanceRepository repo() {
        return new GameInstanceRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.gamesservices.GameInstanceR2dbcRepository.class));
    }

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

    @Test
    void insertPending_roundTrips_pendingPropagationPending() {
        GameInstance i = repo().insertPending("brandx", "minetest", "world1", "alice", null).block();
        assertThat(i).isNotNull();
        assertThat(i.state()).isEqualTo("pending");
        assertThat(i.propagationState()).isEqualTo("pending");
        assertThat(i.ownerSubject()).isEqualTo("alice");
        assertThat(i.endingAt()).isNull();
    }

    @Test
    void casState_isSingleWinner() {
        GameInstanceRepository repo = repo();
        GameInstance i = repo.insertPending("brandx", "veloren", "w", "bob", null).block();
        // pending -> active wins once
        assertThat(repo.casState(i.id(), "active", "pending").block()).isEqualTo(1L);
        // active -> terminated wins once; a second terminate from 'active' is a no-op (now terminated)
        assertThat(repo.casState(i.id(), "terminated", "active").block()).isEqualTo(1L);
        assertThat(repo.casState(i.id(), "terminated", "active").block()).isEqualTo(0L);
    }

    @Test
    void dueForExpiry_selectsOnlyOverdueActive() {
        GameInstanceRepository repo = repo();
        Instant past = Instant.now().minus(1, ChronoUnit.HOURS);
        Instant future = Instant.now().plus(1, ChronoUnit.HOURS);

        GameInstance overdue = repo.insertPending("brandx", "xonotic", "o", "a", past).block();
        repo.casState(overdue.id(), "active", "pending").block();
        GameInstance later = repo.insertPending("brandx", "xonotic", "l", "a", future).block();
        repo.casState(later.id(), "active", "pending").block();
        GameInstance permanent = repo.insertPending("brandx", "xonotic", "p", "a", null).block();
        repo.casState(permanent.id(), "active", "pending").block();

        var due = repo.dueForExpiry(Instant.now()).collectList().block();
        assertThat(due).extracting(GameInstance::id).containsExactly(overdue.id());
    }

    @Test
    void activeByDomain_andDomainsWithActive_scopeToActiveOnly() {
        GameInstanceRepository repo = repo();
        GameInstance a = repo.insertPending("brandx", "mindustry", "a", "u", null).block();
        repo.casState(a.id(), "active", "pending").block();
        repo.insertPending("brandx", "mindustry", "pending-one", "u", null).block(); // stays pending
        GameInstance b = repo.insertPending("brandy", "teeworlds", "b", "u", null).block();
        repo.casState(b.id(), "active", "pending").block();

        assertThat(repo.activeByDomain("brandx").collectList().block())
                .extracting(GameInstance::name).containsExactly("a"); // not the pending one
        assertThat(repo.domainsWithActive().collectList().block())
                .containsExactlyInAnyOrder("brandx", "brandy");
    }

    @Test
    void countNonTerminal_excludesTerminated() {
        GameInstanceRepository repo = repo();
        GameInstance a = repo.insertPending("brandx", "zeroad", "a", "u", null).block();
        repo.insertPending("brandx", "zeroad", "b", "u", null).block();
        assertThat(repo.countNonTerminal("brandx", "zeroad").block()).isEqualTo(2L);
        repo.casState(a.id(), "terminated", "pending").block();
        assertThat(repo.countNonTerminal("brandx", "zeroad").block()).isEqualTo(1L);
    }

    // ── CROSS-DOMAIN read isolation ───────────────────────────────────────────────

    @Test
    void findAll_scopedAdmin_seesOnlyOwnBrand_superadminSeesAll() {
        GameInstanceRepository repo = repo();
        repo.insertPending("brandx", "supertuxkart", "x", "u", null).block();
        repo.insertPending("brandy", "supertuxkart", "y", "u", null).block();

        assertThat(repo.findAll(admin("https://idp.brandx.example")).collectList().block())
                .extracting(GameInstance::domain).containsOnly("brandx");
        assertThat(repo.findAll(superadmin()).collectList().block())
                .extracting(GameInstance::domain).contains("brandx", "brandy");
    }

    @Test
    void findById_scopedAdmin_cannotResolveOtherBrandInstance() {
        GameInstanceRepository repo = repo();
        GameInstance y = repo.insertPending("brandy", "openarena", "y", "u", null).block();
        StepVerifier.create(repo.findById(y.id(), admin("https://idp.brandx.example")))
                .verifyComplete();  // invisible to brand-X admin
        StepVerifier.create(repo.findById(y.id(), superadmin()))
                .assertNext(i -> assertThat(i.domain()).isEqualTo("brandy"))
                .verifyComplete();
    }
}
