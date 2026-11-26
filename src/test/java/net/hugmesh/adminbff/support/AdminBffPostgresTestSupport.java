package net.hugmesh.adminbff.support;

import net.hugmesh.commons.testsupport.PostgresTestSupport;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * admin-BFF specialization of the shared commons {@link PostgresTestSupport} Testcontainers
 * base. The base stands up a single {@code postgres:16-alpine} container and hands each test
 * class a fresh per-class database that the production Liquibase changelog is applied over via
 * the real R2DBC + Liquibase auto-config (replacing the old H2 {@code TestDatabaseConfig}).
 *
 * <p><b>Why this subclass exists:</b> unlike the other BFFs, the admin-BFF changelog carries
 * 114 PostgreSQL-only runtime {@code GRANT … ON <table> TO adminbff_app} changeSets (each guarded
 * by a {@code <dbms type="postgresql"/>} precondition). On the old H2 store those preconditions
 * skipped (MARK_RAN); on a REAL Postgres they EXECUTE — and fail unless the {@code adminbff_app}
 * role exists. In production that least-privilege application role is provisioned by the
 * DB-hardening layer (per-app SCRAM roles), OUTSIDE this app's changelog. The Testcontainers
 * Postgres has no such role, so we create it here, ONCE, at cluster scope (roles are global in
 * Postgres, so a single create covers every per-class database the base spins up). This is
 * test-only wiring — the production changelog is untouched, and the GRANT changeSets now run
 * for real against Postgres exactly as they will in the cluster.
 */
public abstract class AdminBffPostgresTestSupport extends PostgresTestSupport {

    static {
        // The base's static initializer has already started POSTGRES by the time this
        // subclass is loaded. Create the least-privilege application role idempotently on
        // the running cluster (NOLOGIN — it is only a GRANT target here, never connected to).
        try (Connection c = java.sql.DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = c.createStatement()) {
            st.execute(
                    "DO $$ BEGIN "
                  + "  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adminbff_app') THEN "
                  + "    CREATE ROLE adminbff_app NOLOGIN; "
                  + "  END IF; "
                  + "END $$;");
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to create test 'adminbff_app' role on Testcontainers Postgres", e);
        }
    }

    /**
     * Cap each test context's R2DBC pool (hugmesh-admin-bff-api#185).
     *
     * <p>The commons base starts its container at Postgres's default
     * {@code max_connections=100}, and Spring Boot's R2DBC pool defaults to
     * {@code initial-size=10}: every Spring context the TestContext cache keeps alive opens
     * ten connections up front and holds them. Around the tenth cached context the server
     * refuses the next one ("FATAL: sorry, too many clients already", then
     * "Failed to create test database cmtest_N"), and WHICH classes fail moves with test
     * order, so main went red on unrelated classes run after run. One connection up front
     * and at most four per context keeps even a full cache under the ceiling. Spring
     * applies every {@code @DynamicPropertySource} in the class hierarchy, so this adds to
     * the base's database wiring and replaces nothing.
     */
    @DynamicPropertySource
    static void capR2dbcPool(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.pool.initial-size", () -> "1");
        registry.add("spring.r2dbc.pool.max-size", () -> "4");
        registry.add("spring.r2dbc.pool.max-idle-time", () -> "30s");
    }
}
