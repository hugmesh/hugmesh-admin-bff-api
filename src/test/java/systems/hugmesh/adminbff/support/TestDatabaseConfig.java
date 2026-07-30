package systems.hugmesh.adminbff.support;

import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import liquibase.integration.spring.SpringLiquibase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.r2dbc.core.DatabaseClient;
import org.testcontainers.containers.PostgreSQLContainer;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Shared test database wiring backed by a REAL Postgres (Testcontainers) — full
 * production parity, since admin-bff runs on Postgres (r2dbc-postgresql) in prod.
 * This replaces the prior H2-in-PostgreSQL-compatibility-mode store, so H2's
 * NON_KEYWORDS / DATABASE_TO_LOWER quirks (and any behaviour H2-compat masked) are
 * gone: the Liquibase-applied schema and the reactive repositories run on the same
 * engine as production.
 *
 * <p>ONE {@code postgres:16-alpine} container is started once per JVM (static); each
 * test context gets a fresh {@code CREATE DATABASE} so classes stay isolated.
 * Liquibase applies the production changelog over a JDBC datasource and the runtime
 * {@link DatabaseClient} accesses the SAME database reactively via R2DBC.
 *
 * <p>Imported by the full-context tests exactly as before — no test-class change
 * needed; only this wiring moved from H2 to real Postgres.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestDatabaseConfig {

    private static final AtomicInteger DB_SEQ = new AtomicInteger();

    /** Singleton container, reused JVM-wide (per-class container churn races on a
     *  busy Docker host; a single shared db would leak rows across classes — so we
     *  keep one container and a fresh db per context). */
    private static final PostgreSQLContainer<?> POSTGRES;

    static {
        POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");
        POSTGRES.start();
        // The production changelog GRANTs table privileges to the per-app runtime role
        // `admin_bff` (provisioned out-of-band in prod via per-app SCRAM roles, not by the
        // changelog). Create it once on the container — roles are cluster-global in Postgres —
        // so the GRANT changesets apply cleanly. (H2 silently ignored these GRANTs, masking it.)
        try (Connection c = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement s = c.createStatement()) {
            s.execute("CREATE ROLE admin_bff");
        } catch (Exception e) {
            throw new IllegalStateException("failed to create the admin_bff role on the test Postgres", e);
        }
    }

    /** A fresh per-context database keeps test classes isolated. */
    private final String dbName = "adminbff_test_" + DB_SEQ.incrementAndGet();

    public TestDatabaseConfig() {
        try (Connection c = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement s = c.createStatement()) {
            s.execute("CREATE DATABASE " + dbName);
        } catch (Exception e) {
            throw new IllegalStateException("failed to create test database " + dbName, e);
        }
    }

    private String jdbcUrl() {
        return "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getFirstMappedPort() + "/" + dbName;
    }

    private String r2dbcUrl() {
        return "r2dbc:postgresql://" + POSTGRES.getUsername() + ":" + POSTGRES.getPassword()
                + "@" + POSTGRES.getHost() + ":" + POSTGRES.getFirstMappedPort() + "/" + dbName;
    }

    @Bean
    public DataSource liquibaseDataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("org.postgresql.Driver");
        ds.setUrl(jdbcUrl());
        ds.setUsername(POSTGRES.getUsername());
        ds.setPassword(POSTGRES.getPassword());
        return ds;
    }

    /** Apply the production changelog over the per-context Postgres database (runs
     *  before the DatabaseClient is used; @TestConfiguration beans init eagerly). */
    @Bean
    public SpringLiquibase liquibase(DataSource liquibaseDataSource) {
        SpringLiquibase lb = new SpringLiquibase();
        lb.setDataSource(liquibaseDataSource);
        lb.setChangeLog("classpath:db/changelog/db.changelog-master.xml");
        return lb;
    }

    @Bean
    public ConnectionFactory connectionFactory() {
        return ConnectionFactories.get(r2dbcUrl());
    }

    /** The reactive client the repositories use — depends on the Liquibase bean
     *  so the schema is applied before any query runs. */
    @Bean
    public DatabaseClient databaseClient(ConnectionFactory connectionFactory, SpringLiquibase liquibase) {
        return DatabaseClient.create(connectionFactory);
    }
}
