package net.hugmesh.adminbff.domainlock;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * The domain_lock R2DBC repository over a Liquibase-applied H2 (PG-compat) — proves the
 * 009 changelog applies (table + CHECK constraints) and the ADD-active desired-state
 * read/write/CAS round-trips. Mirrors {@code AccessSuspensionRepositoryTest} wiring.
 */
@SpringBootTest(classes = DomainLockRepositoryTest.Boot.class)
@ActiveProfiles("test")
class DomainLockRepositoryTest extends AdminBffPostgresTestSupport {

    // No @ComponentScan — only the H2 DatabaseClient is needed; the repository is
    // constructed directly.
    @org.springframework.boot.SpringBootConfiguration
    @org.springframework.boot.autoconfigure.EnableAutoConfiguration
    static class Boot { }

    @Autowired DatabaseClient db;

    // Clear domain_lock before each test (the H2 store is shared across methods in
    // this class) so activeByRole assertions see only this test's rows.
    @org.junit.jupiter.api.BeforeEach
    void clearTable() {
        db.sql("DELETE FROM domain_lock").fetch().rowsUpdated().block();
    }

    private DomainLockRepository repo() {
        return new DomainLockRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.domainlock.DomainLockRowRepository.class));
    }

    @Test
    void insertActive_thenFindActive_roundTrips() {
        DomainLockRepository repo = repo();
        DomainLock l = repo.insertActive("hugmesh/alice", "alice",
                DomainLock.ROLE_MASTODON_DOMAINLOCKED, "spam-federation", "admin", "default").block();
        assertThat(l).isNotNull();
        assertThat(l.state()).isEqualTo("active");
        assertThat(l.propagationState()).isEqualTo("pending");

        StepVerifier.create(repo.findActive("hugmesh/alice", DomainLock.ROLE_MASTODON_DOMAINLOCKED))
                .assertNext(found -> {
                    assertThat(found.localpart()).isEqualTo("alice");
                    assertThat(found.role()).isEqualTo(DomainLock.ROLE_MASTODON_DOMAINLOCKED);
                    assertThat(found.reason()).isEqualTo("spam-federation");
                })
                .verifyComplete();
    }

    @Test
    void markRemoved_isCompareAndSwap_onlyWinnerGetsOne() {
        DomainLockRepository repo = repo();
        DomainLock l = repo.insertActive("hugmesh/bob", "bob",
                DomainLock.ROLE_MATRIX_DOMAINLOCKED, null, "admin", "default").block();

        // First CAS wins (1 row), second is a no-op (0 rows) — the single-unlock guard.
        assertThat(repo.markRemoved(l.id()).block()).isEqualTo(1L);
        assertThat(repo.markRemoved(l.id()).block()).isEqualTo(0L);

        // No longer active.
        StepVerifier.create(repo.findActive("hugmesh/bob", DomainLock.ROLE_MATRIX_DOMAINLOCKED))
                .verifyComplete();
    }

    @Test
    void activeByRole_isTheForceLocalAllowlistSource() {
        DomainLockRepository repo = repo();
        repo.insertActive("hugmesh/carol", "carol",
                DomainLock.ROLE_MASTODON_DOMAINLOCKED, null, "admin", "default").block();
        repo.insertActive("hugmesh/dave", "dave",
                DomainLock.ROLE_MASTODON_DOMAINLOCKED, null, "admin", "default").block();
        // A different platform role → not in the Mastodon force-local set.
        repo.insertActive("hugmesh/erin", "erin",
                DomainLock.ROLE_MATRIX_DOMAINLOCKED, null, "admin", "default").block();

        var mastodonSet = repo.activeByRole(DomainLock.ROLE_MASTODON_DOMAINLOCKED)
                .collectList().block();
        assertThat(mastodonSet).extracting(DomainLock::localpart)
                .containsExactlyInAnyOrder("carol", "dave");
    }

    @Test
    void activeByLocalpartAndRole_drivesTheForceLocalGuard() {
        DomainLockRepository repo = repo();
        repo.insertActive("hugmesh/frank", "frank",
                DomainLock.ROLE_MATRIX_DOMAINLOCKED, null, "admin", "default").block();

        assertThat(repo.activeByLocalpartAndRole("frank", DomainLock.ROLE_MATRIX_DOMAINLOCKED)
                .hasElements().block()).isTrue();
        // Different role → not locked on that platform.
        assertThat(repo.activeByLocalpartAndRole("frank", DomainLock.ROLE_MASTODON_DOMAINLOCKED)
                .hasElements().block()).isFalse();
    }

    @Test
    void roleCheckConstraint_rejectsUnknownRole() {
        // The DB CHECK (ck_domain_lock_role) rejects a role outside the closed
        // domain-locked vocabulary — a non-controller write path cannot persist a bad
        // row (e.g. an access_suspension role must NOT land here — separate tables).
        StepVerifier.create(db.sql(
                        "INSERT INTO domain_lock "
                        + "(id, casdoor_user, localpart, role, state, created_at, "
                        + " propagation_state, set_by) "
                        + "VALUES ('x', 'u', 'u', 'ROLE_MASTODON', 'active', now(), 'pending', 'admin')")
                        .fetch().rowsUpdated())
                .expectError()
                .verify();
    }
}
