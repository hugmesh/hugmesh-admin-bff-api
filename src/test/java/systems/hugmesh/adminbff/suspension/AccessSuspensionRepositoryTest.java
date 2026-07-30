package systems.hugmesh.adminbff.suspension;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import systems.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * The access_suspension R2DBC repository over a Liquibase-applied H2 (PG-compat) —
 * proves the 008 changelog applies (table + CHECK constraints) and the desired-state
 * read/write/CAS round-trips. Mirrors {@code AccountStoreTest} wiring.
 */
@SpringBootTest(classes = AccessSuspensionRepositoryTest.Boot.class)
@ActiveProfiles("test")
class AccessSuspensionRepositoryTest extends AdminBffPostgresTestSupport {

    // No @ComponentScan (see AccessSyncActionTest.Boot) — only the H2 DatabaseClient
    // is needed; the repository is constructed directly.
    @org.springframework.boot.SpringBootConfiguration
    @org.springframework.boot.autoconfigure.EnableAutoConfiguration
    static class Boot { }

    @Autowired DatabaseClient db;

    private AccessSuspensionRepository repo() {
        return new AccessSuspensionRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.suspension.AccessSuspensionRowRepository.class));
    }

    @Test
    void insertActive_thenFindActive_roundTrips() {
        AccessSuspensionRepository repo = repo();
        AccessSuspension s = repo.insertActive("hugmesh/alice", "alice",
                AccessSuspension.ROLE_MATRIX, null, false, "abuse", "admin", "default").block();
        assertThat(s).isNotNull();
        assertThat(s.state()).isEqualTo("active");
        assertThat(s.propagationState()).isEqualTo("pending");
        assertThat(s.expiresAt()).isNull(); // permanent

        StepVerifier.create(repo.findActive("hugmesh/alice", AccessSuspension.ROLE_MATRIX))
                .assertNext(found -> {
                    assertThat(found.localpart()).isEqualTo("alice");
                    assertThat(found.role()).isEqualTo(AccessSuspension.ROLE_MATRIX);
                    assertThat(found.restoreRole()).isFalse();
                })
                .verifyComplete();
    }

    @Test
    void markRestored_isCompareAndSwap_onlyWinnerGetsOne() {
        AccessSuspensionRepository repo = repo();
        AccessSuspension s = repo.insertActive("hugmesh/bob", "bob",
                AccessSuspension.ROLE_MASTODON, null, true, null, "admin", "default").block();

        // First CAS wins (1 row), second is a no-op (0 rows) — the single-restore guard.
        assertThat(repo.markRestored(s.id()).block()).isEqualTo(1L);
        assertThat(repo.markRestored(s.id()).block()).isEqualTo(0L);

        // No longer active.
        StepVerifier.create(repo.findActive("hugmesh/bob", AccessSuspension.ROLE_MASTODON))
                .verifyComplete();
    }

    @Test
    void dueForRestore_selectsOnlyExpiredActiveRestorable() {
        AccessSuspensionRepository repo = repo();
        Instant past = Instant.now().minus(1, ChronoUnit.HOURS);
        Instant future = Instant.now().plus(1, ChronoUnit.HOURS);

        // Overdue + restorable → due.
        AccessSuspension overdue = repo.insertActive("hugmesh/carol", "carol",
                AccessSuspension.ROLE_MATRIX, past, true, null, "admin", "default").block();
        // Future TTL → not yet due.
        repo.insertActive("hugmesh/dave", "dave",
                AccessSuspension.ROLE_MATRIX, future, true, null, "admin", "default").block();
        // Permanent (no TTL) → never due.
        repo.insertActive("hugmesh/erin", "erin",
                AccessSuspension.ROLE_MASTODON, null, false, null, "admin", "default").block();

        var due = repo.dueForRestore(Instant.now()).collectList().block();
        assertThat(due).extracting(AccessSuspension::id).containsExactly(overdue.id());
    }

    @Test
    void activeByLocalpartAndRole_drivesTheBrokerGuard() {
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/frank", "frank",
                AccessSuspension.ROLE_MATRIX, null, false, null, "admin", "default").block();

        assertThat(repo.activeByLocalpartAndRole("frank", AccessSuspension.ROLE_MATRIX)
                .hasElements().block()).isTrue();
        // Different role → not suspended on that platform.
        assertThat(repo.activeByLocalpartAndRole("frank", AccessSuspension.ROLE_MASTODON)
                .hasElements().block()).isFalse();
    }

    @Test
    void roleCheckConstraint_acceptsRoleMesh_afterChangeset330() {
        // Changeset 330 widened ck_access_suspension_role with ROLE_MESH (008 created it
        // with the original three values). Without that migration this insert fails the
        // CHECK — so this round-trip is the proof the changelog actually applied, not just
        // that the Java constant exists.
        AccessSuspensionRepository repo = repo();
        AccessSuspension s = repo.insertActive("hugmesh/mallory", "mallory",
                AccessSuspension.ROLE_MESH, null, false, "mesh-abuse", "admin", "default").block();
        assertThat(s).isNotNull();
        assertThat(s.role()).isEqualTo("ROLE_MESH");

        // ... and it is readable back through the SAME desired-state read the reconcile
        // loop uses, so a mesh ban is a first-class row rather than a write-only artefact.
        StepVerifier.create(repo.findActive("hugmesh/mallory", AccessSuspension.ROLE_MESH))
                .assertNext(found -> {
                    assertThat(found.localpart()).isEqualTo("mallory");
                    assertThat(found.state()).isEqualTo("active");
                    assertThat(found.reason()).isEqualTo("mesh-abuse");
                })
                .verifyComplete();
    }

    @Test
    void roleCheckConstraint_rejectsUnknownRole() {
        // The DB CHECK (ck_access_suspension_role) rejects a role outside the closed
        // vocabulary — a non-controller write path cannot persist a bad row.
        StepVerifier.create(db.sql(
                        "INSERT INTO access_suspension "
                        + "(id, casdoor_user, localpart, role, state, suspended_at, "
                        + " restore_role, propagation_state, set_by) "
                        + "VALUES ('x', 'u', 'u', 'ROLE_BOGUS', 'active', now(), true, 'pending', 'admin')")
                        .fetch().rowsUpdated())
                .expectError()
                .verify();
    }
}
