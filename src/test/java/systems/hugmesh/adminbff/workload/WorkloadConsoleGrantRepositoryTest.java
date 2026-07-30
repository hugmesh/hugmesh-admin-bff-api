package systems.hugmesh.adminbff.workload;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code workload_console_grant} R2DBC repository over a Liquibase-applied H2 (PG-compat).
 * Proves the 110 changelog applies + the cloned-from-011 idioms:
 * <ul>
 *   <li>insert records a READ_ONLY, TTL'd, active grant; findActive returns it;</li>
 *   <li>the scoped list returns ONLY the caller's-domain rows (two-domain DENY isolation);
 *       SUPERADMIN (unscoped) sees both;</li>
 *   <li>revoke is a single-winner CAS active-&gt;revoked (a second call is a no-op);</li>
 *   <li>dueForExpiry selects only past-TTL active rows; markExpired CASes active-&gt;expired.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class WorkloadConsoleGrantRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM workload_console_grant").fetch().rowsUpdated().block();
    }

    private WorkloadConsoleGrantRepository repo() {
        return new WorkloadConsoleGrantRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.workload.WorkloadConsoleGrantR2dbcRepository.class));
    }

    private WorkloadConsoleGrant draft(String grantee, String domain, boolean logAccess, Instant exp) {
        return new WorkloadConsoleGrant(null, grantee, domain, WorkloadConsoleGrant.ACCESS_READ_ONLY,
                logAccess, WorkloadConsoleGrant.STATE_ACTIVE, "root", null, exp, null, null, domain,
                WorkloadConsoleGrant.PROP_PENDING, 1);
    }

    @Test
    void insertAndFindActive_recordsReadOnlyTtlGrant() {
        WorkloadConsoleGrantRepository repo = repo();
        Instant exp = Instant.now().plus(24, ChronoUnit.HOURS);
        WorkloadConsoleGrant g = repo.insertActive(draft("alice", "brandx", false, exp), 1).block();

        assertThat(g).isNotNull();
        assertThat(g.id()).isNotBlank();
        assertThat(g.accessLevel()).isEqualTo(WorkloadConsoleGrant.ACCESS_READ_ONLY);
        assertThat(g.logAccess()).isFalse();
        assertThat(g.state()).isEqualTo(WorkloadConsoleGrant.STATE_ACTIVE);

        WorkloadConsoleGrant found = repo.findActive("alice", "brandx").block();
        assertThat(found).isNotNull();
        assertThat(found.isLiveAt(Instant.now())).isTrue();
    }

    @Test
    void scopedList_isolatesByDomain_superadminSeesAll() {
        WorkloadConsoleGrantRepository repo = repo();
        Instant exp = Instant.now().plus(24, ChronoUnit.HOURS);
        repo.insertActive(draft("alice", "brandx", true, exp), 1).block();
        repo.insertActive(draft("bob", "brandy", false, exp), 2).block();

        PrincipalDomain brandx = WorkloadScopeFixtures.adminScope("brandx");
        assertThat(repo.list(brandx).collectList().block()).hasSize(1);
        assertThat(repo.list(brandx).blockFirst().targetDomain()).isEqualTo("brandx");

        PrincipalDomain su = WorkloadScopeFixtures.superadminScope();
        assertThat(repo.list(su).collectList().block()).hasSize(2);
    }

    @Test
    void revoke_isSingleWinnerCas() {
        WorkloadConsoleGrantRepository repo = repo();
        Instant exp = Instant.now().plus(24, ChronoUnit.HOURS);
        WorkloadConsoleGrant g = repo.insertActive(draft("alice", "brandx", false, exp), 1).block();

        Long first = repo.revoke(g.id(), "root", 2).block();
        Long second = repo.revoke(g.id(), "root", 3).block();
        assertThat(first).isEqualTo(1L);
        assertThat(second).isEqualTo(0L);

        WorkloadConsoleGrant after = repo.findById(g.id()).block();
        assertThat(after.state()).isEqualTo(WorkloadConsoleGrant.STATE_REVOKED);
        assertThat(repo.findActive("alice", "brandx").block()).isNull();
    }

    @Test
    void expirySweep_selectsAndMarksOnlyPastTtlActiveRows() {
        WorkloadConsoleGrantRepository repo = repo();
        Instant past = Instant.now().minus(1, ChronoUnit.HOURS);
        Instant future = Instant.now().plus(24, ChronoUnit.HOURS);
        WorkloadConsoleGrant expired = repo.insertActive(draft("alice", "brandx", false, past), 1).block();
        repo.insertActive(draft("bob", "brandy", false, future), 2).block();

        var due = repo.dueForExpiry(Instant.now()).collectList().block();
        assertThat(due).hasSize(1);
        assertThat(due.get(0).id()).isEqualTo(expired.id());

        Long n = repo.markExpired(expired.id(), 3).block();
        assertThat(n).isEqualTo(1L);
        assertThat(repo.findById(expired.id()).block().state())
                .isEqualTo(WorkloadConsoleGrant.STATE_EXPIRED);
    }
}
