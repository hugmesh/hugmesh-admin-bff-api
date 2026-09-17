package net.hugmesh.adminbff.mfa;

import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code role_mfa_policy} R2DBC repository over the Liquibase-applied Postgres
 * (Testcontainers) — proves the 150 changeSet's table + {@code uq_role_mfa_policy_domain_role}
 * are what the UPSERT converges on, that the DOMAIN-SCOPED predicates hold (brand X's rows never
 * surface in brand Y's reads), and that {@code methods = NULL} ("any") round-trips as NULL
 * rather than an empty string.
 *
 * <p>The test connection is the container superuser, so it can {@code DELETE} for setup;
 * production's {@code adminbff_app} cannot, which is why the repository declares no delete.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class RoleMfaPolicyRepositoryTest {

    @Autowired DatabaseClient db;

    private RoleMfaPolicyR2dbcRepository repo;

    @BeforeEach
    void setup() {
        db.sql("DELETE FROM role_mfa_policy").fetch().rowsUpdated().block();
        repo = R2dbcRepos.of(db, RoleMfaPolicyR2dbcRepository.class);
    }

    @Test
    void upsert_insertsThenUpdates_convergingOnOneRow_withAStableId() {
        assertThat(repo.upsert("id-1", "brandx", "mod", false, null, 0L, "alice").block()).isEqualTo(1L);
        RoleMfaPolicyRow first = repo.findByDomainAndRole("brandx", "mod").block();
        assertThat(first).isNotNull();
        assertThat(first.id()).isEqualTo("id-1");
        assertThat(first.required()).isFalse();
        assertThat(first.methods()).isNull();
        assertThat(first.updatedBy()).isEqualTo("alice");
        assertThat(first.updatedAt()).isNotNull();

        // Same (domain, role), a DIFFERENT candidate id: the UNIQUE constraint routes it to the
        // UPDATE arm, the original id survives, and every value converges on the new write.
        assertThat(repo.upsert("id-2", "brandx", "mod", true, "webauthn,otp", 300L, "bob").block()).isEqualTo(1L);
        List<RoleMfaPolicyRow> rows = repo.findByDomainOrderByRole("brandx").collectList().block();
        assertThat(rows).hasSize(1);
        RoleMfaPolicyRow second = rows.get(0);
        assertThat(second.id()).as("ON CONFLICT keeps the existing PK").isEqualTo("id-1");
        assertThat(second.required()).isTrue();
        assertThat(second.methods()).isEqualTo("webauthn,otp");
        assertThat(second.graceSeconds()).isEqualTo(300L);
        assertThat(second.updatedBy()).isEqualTo("bob");
        assertThat(second.updatedAt()).isAfterOrEqualTo(first.updatedAt());
    }

    @Test
    void reads_areDomainScoped_crossBrandIsolation() {
        repo.upsert("x-admin", "brandx", "admin", true, null, 0L, "alice").block();
        repo.upsert("x-mod", "brandx", "mod", true, "webauthn", 0L, "alice").block();
        repo.upsert("y-mod", "brandy", "mod", false, null, 60L, "yvonne").block();

        assertThat(repo.findByDomainOrderByRole("brandx").map(RoleMfaPolicyRow::role).collectList().block())
                .containsExactly("admin", "mod");
        assertThat(repo.findByDomainOrderByRole("brandy").map(RoleMfaPolicyRow::role).collectList().block())
                .containsExactly("mod");
        // DENY: brand Y's mod row is never brand X's.
        RoleMfaPolicyRow xmod = repo.findByDomainAndRole("brandx", "mod").block();
        assertThat(xmod.required()).isTrue();
        assertThat(xmod.updatedBy()).isEqualTo("alice");
        RoleMfaPolicyRow ymod = repo.findByDomainAndRole("brandy", "mod").block();
        assertThat(ymod.required()).isFalse();
        assertThat(ymod.updatedBy()).isEqualTo("yvonne");
        assertThat(repo.findByDomainAndRole("brandy", "admin").blockOptional()).isEmpty();
    }

    @Test
    void findByDomainAndRoleIn_returnsOnlyTheRequestedRoles_inThatDomain() {
        repo.upsert("x-admin", "brandx", "admin", true, null, 0L, "alice").block();
        repo.upsert("x-mod", "brandx", "mod", true, null, 0L, "alice").block();
        repo.upsert("x-user", "brandx", "user", false, null, 0L, "alice").block();
        repo.upsert("y-mod", "brandy", "mod", true, null, 0L, "yvonne").block();

        List<RoleMfaPolicyRow> rows = repo.findByDomainAndRoleIn("brandx", Set.of("mod", "user", "fleet_admin"))
                .collectList().block();
        assertThat(rows).extracting(RoleMfaPolicyRow::role).containsExactlyInAnyOrder("mod", "user");
        assertThat(rows).allMatch(r -> r.domain().equals("brandx"));
    }

    @Test
    void methods_nullMeansAny_andRoundTripsAsNull_notEmptyString() {
        repo.upsert("x-mod", "brandx", "mod", true, null, 0L, "alice").block();
        assertThat(repo.findByDomainAndRole("brandx", "mod").block().methods()).isNull();
        repo.upsert("x-mod", "brandx", "mod", true, "recovery", 0L, "alice").block();
        assertThat(repo.findByDomainAndRole("brandx", "mod").block().methods()).isEqualTo("recovery");
        // back to any
        repo.upsert("x-mod", "brandx", "mod", true, null, 0L, "alice").block();
        assertThat(repo.findByDomainAndRole("brandx", "mod").block().methods()).isNull();
    }
}
