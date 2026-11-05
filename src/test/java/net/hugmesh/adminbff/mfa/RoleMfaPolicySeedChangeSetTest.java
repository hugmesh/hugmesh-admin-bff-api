package net.hugmesh.adminbff.mfa;

import net.hugmesh.adminbff.support.TestDatabaseConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The 380 band over the Liquibase-applied Postgres (Testcontainers): the four default
 * {@code role_mfa_policy} rows for the {@code default} domain are what the #3 plan says
 * (superadmin and admin required, mod relaxable, user optional), carry the schema defaults
 * for the rest, and the runtime GRANT on the table still targets {@code adminbff_app}
 * (never {@code admin_bff}) with exactly SELECT, INSERT, UPDATE.
 *
 * <p>No {@code DELETE} setup here, unlike {@link RoleMfaPolicyRepositoryTest}: this class
 * reads the table exactly as the changelog left it. The marker property below makes this
 * context distinct from that class's (Spring caches contexts by configuration; sharing one
 * would hand this class a database the sibling has already emptied), so a FRESH per-context
 * database is created and the changelog, 380 included, is applied over it for this class.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
@TestPropertySource(properties = "hugmesh.test.context-marker=role-mfa-policy-seed-380")
class RoleMfaPolicySeedChangeSetTest {

    @Autowired DatabaseClient db;

    private List<Map<String, Object>> rows(String sql) {
        return db.sql(sql).fetch().all().collectList().block();
    }

    @Test
    void theFourSeedChangeSets_ranForReal_notMarkRan() {
        List<Map<String, Object>> runs = rows(
                "SELECT id, exectype FROM databasechangelog WHERE id LIKE '380-%' ORDER BY id");
        assertThat(runs).extracting(r -> r.get("id") + ":" + r.get("exectype")).containsExactly(
                "380-1-role-mfa-policy-seed-superadmin:EXECUTED",
                "380-2-role-mfa-policy-seed-admin:EXECUTED",
                "380-3-role-mfa-policy-seed-mod:EXECUTED",
                "380-4-role-mfa-policy-seed-user:EXECUTED");
    }

    @Test
    void theDefaultDomain_hasExactlyTheFourPlannedRows_withThePlannedRequiredFlags() {
        List<Map<String, Object>> rows = rows(
                "SELECT role, required, methods, grace_seconds, updated_by, updated_at, created_at"
                        + " FROM role_mfa_policy WHERE domain = 'default' ORDER BY role");
        assertThat(rows).extracting(r -> r.get("role")).containsExactly("admin", "mod", "superadmin", "user");

        Map<String, Boolean> required = Map.of("superadmin", true, "admin", true, "mod", false, "user", false);
        for (Map<String, Object> row : rows) {
            String role = (String) row.get("role");
            assertThat(row.get("required")).as(role + ".required").isEqualTo(required.get(role));
            assertThat(row.get("methods")).as(role + ".methods is NULL (= any)").isNull();
            assertThat(((Number) row.get("grace_seconds")).longValue()).as(role + ".grace_seconds").isZero();
            assertThat(row.get("updated_by")).as(role + ".updated_by").isEqualTo("seed:380");
            assertThat(row.get("updated_at")).as(role + ".updated_at (never edited)").isNull();
            assertThat(row.get("created_at")).as(role + ".created_at (column default)").isNotNull();
        }
    }

    @Test
    void theSeedRows_matchTheServiceDefaults_soEnforcementIsUnchangedByTheBand() {
        for (Map<String, Object> row : rows("SELECT role, required FROM role_mfa_policy WHERE domain = 'default'")) {
            String role = (String) row.get("role");
            assertThat(row.get("required")).as(role)
                    .isEqualTo(RoleMfaPolicyService.DEFAULT_REQUIRED.get(role));
        }
        assertThat(rows("SELECT role FROM role_mfa_policy WHERE domain = 'default'"))
                .extracting(r -> r.get("role"))
                .containsExactlyInAnyOrderElementsOf(RoleMfaPolicyService.CANONICAL_ROLES);
    }

    @Test
    void theSeedIds_areTheOnesTheRollbackDeletes() {
        List<Map<String, Object>> rows = rows(
                "SELECT id, role FROM role_mfa_policy WHERE domain = 'default' ORDER BY role");
        assertThat(rows).extracting(r -> r.get("role") + "=" + r.get("id")).containsExactly(
                "admin=3fb53de4-8682-4184-9180-f24703431f38",
                "mod=618fc816-1480-466e-be36-9665de2e7247",
                "superadmin=493fd20a-7a82-42b5-9df1-e3663733e8c3",
                "user=dfd40967-1f04-4d29-bd18-834c05e2c657");
    }

    @Test
    void noOtherDomain_wasSeeded() {
        assertThat(rows("SELECT DISTINCT domain FROM role_mfa_policy"))
                .extracting(r -> r.get("domain")).containsExactly("default");
    }

    @Test
    void theRuntimeRole_isAdminbffApp_withSelectInsertUpdate_andNoDelete() {
        List<Map<String, Object>> grants = rows(
                "SELECT grantee, privilege_type FROM information_schema.role_table_grants"
                        + " WHERE table_name = 'role_mfa_policy' AND grantee = 'adminbff_app'"
                        + " ORDER BY privilege_type");
        assertThat(grants).extracting(g -> g.get("privilege_type"))
                .containsExactly("INSERT", "SELECT", "UPDATE");
        assertThat(rows("SELECT 1 AS one FROM information_schema.role_table_grants"
                + " WHERE table_name = 'role_mfa_policy' AND grantee = 'admin_bff'"))
                .as("the gateway's role never receives a grant here").isEmpty();
    }
}
