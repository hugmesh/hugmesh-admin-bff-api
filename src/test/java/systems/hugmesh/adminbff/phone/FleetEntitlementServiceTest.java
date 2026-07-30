package systems.hugmesh.adminbff.phone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * The {@link FleetEntitlementService} gate end-to-end over the real Liquibase Postgres (changeset
 * 306) — the entitlement wall the public fleet-owner surface consults. Every assertion reads the
 * STORE (never an echo); the expiry is evaluated against the DB clock. Proves:
 * <ul>
 *   <li>{@code isEntitled} is TRUE only for an ACTIVE, unexpired row — FALSE for no row, an
 *       inactive row, an expired row (past {@code expires_at}), and a just-expired boundary row;
 *       a NULL {@code expires_at} never expires;</li>
 *   <li>a null / blank subject fails closed WITHOUT ever querying (the guard short-circuits);</li>
 *   <li>{@code upsert} is a portable UPDATE-then-INSERT: the first call INSERTs, a second call for
 *       the same subject UPDATEs in place (no duplicate, values replaced) — and the isEntitled
 *       read reflects the newly-written row;</li>
 *   <li>{@code delete} revokes (rows-deleted; 0 for an absent subject) and {@code list} is
 *       subject-ordered.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class FleetEntitlementServiceTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM fleet_entitlement").fetch().rowsUpdated().block();
    }

    private FleetEntitlementService service() {
        return new FleetEntitlementService(systems.hugmesh.adminbff.testutil.R2dbcRepos
                .of(db, FleetEntitlementRowRepository.class));
    }

    // ── isEntitled matrix (fail-closed, DB-clock expiry) ─────────────────────────────
    @Test
    void isEntitled_trueOnlyForActiveUnexpiredRow() {
        FleetEntitlementService svc = service();

        // No row at all -> false.
        assertThat(svc.isEntitled("nobody").block()).isFalse();

        // Active + no expiry -> true (a NULL expires_at never expires).
        svc.upsert("active-forever", true, null, null).block();
        assertThat(svc.isEntitled("active-forever").block()).isTrue();

        // Active + far-future expiry -> true.
        svc.upsert("active-future", true, 3, Instant.now().plusSeconds(3600)).block();
        assertThat(svc.isEntitled("active-future").block()).isTrue();

        // Active + PAST expiry -> false (expired against the DB clock).
        svc.upsert("expired-past", true, 3, Instant.now().minusSeconds(3600)).block();
        assertThat(svc.isEntitled("expired-past").block()).isFalse();

        // Active + JUST-expired boundary (1s ago) -> false: the query runs after the write, so the
        // DB clock is strictly past a 1-second-ago stamp -> reliably NOT entitled.
        svc.upsert("expired-now", true, 3, Instant.now().minusSeconds(1)).block();
        assertThat(svc.isEntitled("expired-now").block()).isFalse();

        // INACTIVE (even with no expiry) -> false.
        svc.upsert("inactive", false, 3, null).block();
        assertThat(svc.isEntitled("inactive").block()).isFalse();
    }

    @Test
    void isEntitled_nullOrBlankSubject_failsClosed_withoutQuerying() {
        // Use a Mockito-mocked repo to PROVE the guard short-circuits before any DB round-trip.
        FleetEntitlementRowRepository repo = org.mockito.Mockito.mock(FleetEntitlementRowRepository.class);
        FleetEntitlementService svc = new FleetEntitlementService(repo);

        assertThat(svc.isEntitled(null).block()).isFalse();
        assertThat(svc.isEntitled("").block()).isFalse();
        assertThat(svc.isEntitled("   ").block()).isFalse();
        verify(repo, never()).countEntitled(org.mockito.ArgumentMatchers.any());
    }

    // ── upsert: INSERT then UPDATE-in-place, read reflects the written row ────────────
    @Test
    void upsert_insertsThenUpdatesInPlace_readReflectsWrite() {
        FleetEntitlementService svc = service();

        FleetEntitlement first = svc.upsert("sub-1", true, 5, null).block();
        assertThat(first).isNotNull();
        assertThat(first.subject()).isEqualTo("sub-1");
        assertThat(first.active()).isTrue();
        assertThat(first.seats()).isEqualTo(5);
        assertThat(svc.isEntitled("sub-1").block()).isTrue();

        // Second upsert for the SAME subject UPDATEs in place — no duplicate row, values replaced.
        FleetEntitlement second = svc.upsert("sub-1", false, 9, null).block();
        assertThat(second.active()).isFalse();
        assertThat(second.seats()).isEqualTo(9);
        assertThat(svc.list().collectList().block()).hasSize(1);      // still exactly one row
        assertThat(svc.isEntitled("sub-1").block()).isFalse();        // now inactive -> gate closed

        // Re-activating flips the gate back open.
        svc.upsert("sub-1", true, 9, null).block();
        assertThat(svc.isEntitled("sub-1").block()).isTrue();
    }

    // ── delete + list ────────────────────────────────────────────────────────────────
    @Test
    void delete_revokes_andReturnsRowsDeleted() {
        FleetEntitlementService svc = service();
        svc.upsert("sub-1", true, null, null).block();
        assertThat(svc.isEntitled("sub-1").block()).isTrue();

        assertThat(svc.delete("sub-1").block()).isEqualTo(1L);
        assertThat(svc.find("sub-1").block()).isNull();
        assertThat(svc.isEntitled("sub-1").block()).isFalse();

        // Deleting an absent subject is a clean 0.
        assertThat(svc.delete("never-existed").block()).isEqualTo(0L);
    }

    @Test
    void list_isSubjectOrdered() {
        FleetEntitlementService svc = service();
        svc.upsert("sub-c", true, null, null).block();
        svc.upsert("sub-a", true, null, null).block();
        svc.upsert("sub-b", true, null, null).block();

        var subjects = svc.list().map(FleetEntitlement::subject).collectList().block();
        assertThat(subjects).containsExactly("sub-a", "sub-b", "sub-c");
    }

    @Test
    void find_absentSubject_isEmpty() {
        assertThat(service().find("ghost").block()).isNull();
    }

    /** Sanity: the reactive contract never emits null Booleans (defaultIfEmpty is honoured). */
    @Test
    void isEntitled_neverEmpty() {
        Mono<Boolean> m = service().isEntitled("nobody-here");
        assertThat(m.hasElement().block()).isTrue();
    }
}
