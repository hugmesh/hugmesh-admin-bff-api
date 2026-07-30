package systems.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code service_deployment} R2DBC repository over a Liquibase-applied H2 (PG-compat) —
 * proves the 102 changelog applies and:
 * <ul>
 *   <li>insert records created_at + ending_at + enforce_actions + created_by_subject;</li>
 *   <li>the scoped list ({@link ServiceDeploymentRepository#listForScope}) returns ONLY the
 *       caller's-domain rows (two-domain DENY isolation); SUPERADMIN scope sees all;</li>
 *   <li>{@link ServiceDeploymentRepository#dueForEnding} selects only ACTIVE rows past their
 *       ending_at (no-expiry rows excluded);</li>
 *   <li>{@link ServiceDeploymentRepository#markEnded} is a single-winner CAS that stamps
 *       ended_at; a second call is a no-op (rows == 0);</li>
 *   <li>propagation_state updates.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class ServiceDeploymentRepositoryTest {

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        // The @DataR2dbcTest H2 store is per-CLASS; clear between methods.
        db.sql("DELETE FROM service_deployment").fetch().rowsUpdated().block();
    }

    private ServiceDeploymentRepository repo() {
        return new ServiceDeploymentRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.servicecatalog.ServiceDeploymentR2dbcRepository.class));
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private static PrincipalDomain scoped(String domain) {
        return ScopeFixtures.admin(domain, REGISTRY);
    }

    @Test
    void insert_recordsCreatedAtEndingAtAndEnforceActions() {
        ServiceDeploymentRepository repo = repo();
        Instant ending = Instant.now().plus(7, ChronoUnit.DAYS);
        ServiceDeployment d = repo.insertActive("brandx", "owncast", "small-postgres",
                ending, "teardown,revoke-roles,revoke-certs,alert", "root@infra").block();

        assertThat(d).isNotNull();
        assertThat(d.id()).isNotBlank();
        assertThat(d.state()).isEqualTo(ServiceDeployment.STATE_ACTIVE);
        assertThat(d.createdBySubject()).isEqualTo("root@infra");

        ServiceDeployment found = repo.findById(d.id()).block();
        assertThat(found).isNotNull();
        assertThat(found.createdAt()).isNotNull();                       // created_at recorded
        assertThat(found.endingAt()).isCloseTo(ending,                   // ending_at recorded
                org.assertj.core.api.Assertions.within(2, ChronoUnit.SECONDS));
        assertThat(found.enforceActions()).isEqualTo("teardown,revoke-roles,revoke-certs,alert");
        assertThat(found.propagationState()).isEqualTo(ServiceDeployment.PROP_PENDING);
        assertThat(found.endedAt()).isNull();
    }

    @Test
    void insert_noExpiry_endingAtNull() {
        ServiceDeployment d = repo().insertActive("brandx", "phpbb", null, null, "alert", "root").block();
        assertThat(d.endingAt()).isNull();
    }

    @Test
    void listForScope_isTwoDomainIsolated_superadminSeesAll() {
        ServiceDeploymentRepository repo = repo();
        repo.insertActive("brandx", "owncast", null, null, "teardown", "root").block();
        repo.insertActive("brandy", "phpbb", null, null, "teardown", "root").block();

        List<ServiceDeployment> x = repo.listForScope(scoped("brandx")).collectList().block();
        assertThat(x).extracting(ServiceDeployment::domain).containsOnly("brandx");
        // DENY isolation: brand X never sees brand Y's deployment.
        assertThat(x).extracting(ServiceDeployment::serviceKey).containsExactly("owncast");

        List<ServiceDeployment> all = repo.listForScope(ScopeFixtures.superadmin(REGISTRY))
                .collectList().block();
        assertThat(all).extracting(ServiceDeployment::domain)
                .containsExactlyInAnyOrder("brandx", "brandy");
    }

    @Test
    void dueForEnding_selectsOnlyActivePastEndingAt_excludesNoExpiry() {
        ServiceDeploymentRepository repo = repo();
        // overdue (active, ending in the past) -> due
        ServiceDeployment overdue = repo.insertActive("brandx", "owncast", null,
                Instant.now().minusSeconds(60), "teardown", "root").block();
        // future ending -> not due
        repo.insertActive("brandx", "akkoma", null, Instant.now().plusSeconds(3600), "teardown", "root").block();
        // no-expiry -> never due
        repo.insertActive("brandx", "phpbb", null, null, "teardown", "root").block();

        List<ServiceDeployment> due = repo.dueForEnding(Instant.now()).collectList().block();
        assertThat(due).extracting(ServiceDeployment::id).containsExactly(overdue.id());
    }

    @Test
    void markEnded_singleWinnerCas_stampsEndedAt() {
        ServiceDeploymentRepository repo = repo();
        ServiceDeployment d = repo.insertActive("brandx", "owncast", null,
                Instant.now().minusSeconds(1), "teardown", "root").block();

        assertThat(repo.markEnded(d.id()).block()).isEqualTo(1L);     // first wins
        assertThat(repo.markEnded(d.id()).block()).isEqualTo(0L);     // idempotent no-op

        ServiceDeployment ended = repo.findById(d.id()).block();
        assertThat(ended.state()).isEqualTo(ServiceDeployment.STATE_ENDED);
        assertThat(ended.endedAt()).isNotNull();
        // An ended row is no longer in the due set.
        assertThat(repo.dueForEnding(Instant.now()).collectList().block()).isEmpty();
    }

    @Test
    void updatePropagationState_records() {
        ServiceDeploymentRepository repo = repo();
        ServiceDeployment d = repo.insertActive("brandx", "owncast", null, null, "teardown", "root").block();
        repo.updatePropagationState(d.id(), ServiceDeployment.PROP_APPLIED).block();
        assertThat(repo.findById(d.id()).block().propagationState())
                .isEqualTo(ServiceDeployment.PROP_APPLIED);
    }
}
