package net.hugmesh.adminbff.backingservices;

import liquibase.integration.spring.SpringLiquibase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Liquibase changeSet 350 ({@code 350-backing-service-id-velero-objectstore.xml},
 * hugmesh-admin-bff-api#58 / decision 92): a stored {@code backing_service_mode} row whose
 * {@code service_id} is the retired {@code object-store} is rewritten to the registry id
 * {@code velero-objectstore}, every other column and every other row is left alone, and a
 * second execution changes nothing.
 *
 * <p><b>Engine: H2 in PostgreSQL mode, NOT Postgres.</b> The production changelog's shared test
 * harness ({@code TestDatabaseConfig}) needs Docker/Testcontainers; this test applies ONLY the
 * 310 table changelog and the 350 changelog (both portable; 310's PG-only index/GRANT changeSets
 * MARK_RAN on H2) through the same {@link SpringLiquibase} the application uses, so it runs
 * anywhere. The UPDATE is a plain {@code <update>} with a string-literal WHERE, so the engine
 * difference is not load-bearing — but a Postgres run is still the real proof, and happens
 * wherever the Testcontainers suites run.
 */
class BackingServiceIdRenameMigrationTest {

    private static final String CL_310 = "classpath:db/changelog/310-backing-service-mode.xml";
    private static final String CL_350 = "classpath:db/changelog/350-backing-service-id-velero-objectstore.xml";

    private SingleConnectionDataSource ds;
    private JdbcTemplate jdbc;

    @BeforeEach
    void freshDatabase() throws Exception {
        ds = new SingleConnectionDataSource(
                "jdbc:h2:mem:bsm350-" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                "sa", "", true);
        jdbc = new JdbcTemplate(ds);
        apply(CL_310);
    }

    @AfterEach
    void close() {
        jdbc.execute("SHUTDOWN");
        ds.destroy();
    }

    private void apply(String changelog) throws Exception {
        SpringLiquibase lb = new SpringLiquibase();
        lb.setDataSource(ds);
        lb.setChangeLog(changelog);
        lb.setShouldRun(true);
        lb.afterPropertiesSet();
    }

    private void row(String id, String serviceId, String mode, String endpoint, long generation) {
        jdbc.update("INSERT INTO backing_service_mode (id, service_id, mode, endpoint, creds_ref, "
                        + "requested_by_subject, generation) VALUES (?, ?, ?, ?, ?, ?, ?)",
                id, serviceId, mode, endpoint, "ref/" + id, "actor-" + id, generation);
    }

    private Map<String, Object> byId(String id) {
        return jdbc.queryForMap("SELECT service_id, mode, endpoint, creds_ref, requested_by_subject, "
                + "generation FROM backing_service_mode WHERE id = ?", id);
    }

    private long count(String serviceId) {
        Long n = jdbc.queryForObject(
                "SELECT COUNT(*) FROM backing_service_mode WHERE service_id = ?", Long.class, serviceId);
        return n == null ? 0 : n;
    }

    @Test
    void rewritesRetiredObjectStoreRows_andTouchesNothingElse() throws Exception {
        row("a1", "object-store", "managed", "s3.example.net", 1);
        row("a2", "kafka", "managed", "b.msk:9094", 2);
        row("a3", "object-store", "self-hosted", null, 3);
        // near-misses the WHERE must not match
        row("a4", "object-store-archive", "managed", "x.example.net", 4);
        row("a5", "OBJECT-STORE", "managed", "y.example.net", 5);

        apply(CL_350);

        assertThat(count("object-store")).isZero();
        assertThat(count("velero-objectstore")).isEqualTo(2);
        Map<String, Object> a1 = byId("a1");
        assertThat(a1.get("SERVICE_ID")).isEqualTo("velero-objectstore");
        assertThat(a1.get("MODE")).isEqualTo("managed");
        assertThat(a1.get("ENDPOINT")).isEqualTo("s3.example.net");
        assertThat(a1.get("CREDS_REF")).isEqualTo("ref/a1");
        assertThat(a1.get("REQUESTED_BY_SUBJECT")).isEqualTo("actor-a1");
        assertThat(((Number) a1.get("GENERATION")).longValue()).isEqualTo(1L);
        assertThat(byId("a3").get("SERVICE_ID")).isEqualTo("velero-objectstore");
        assertThat(((Number) byId("a3").get("GENERATION")).longValue()).isEqualTo(3L);
        assertThat(byId("a2").get("SERVICE_ID")).isEqualTo("kafka");
        assertThat(byId("a4").get("SERVICE_ID")).isEqualTo("object-store-archive");
        assertThat(byId("a5").get("SERVICE_ID")).isEqualTo("OBJECT-STORE");
    }

    @Test
    void isIdempotent_aSecondExecutionChangesNothing() throws Exception {
        row("b1", "object-store", "managed", "s3.example.net", 1);
        apply(CL_350);
        List<Map<String, Object>> after1 = jdbc.queryForList(
                "SELECT * FROM backing_service_mode ORDER BY id");

        // Force Liquibase to RE-EXECUTE 350 (it would otherwise skip an already-run changeSet).
        int forgotten = jdbc.update("DELETE FROM DATABASECHANGELOG WHERE ID = ?",
                "350-backing-service-id-velero-objectstore");
        assertThat(forgotten).as("350 was recorded as run").isEqualTo(1);
        apply(CL_350);

        assertThat(jdbc.queryForList("SELECT * FROM backing_service_mode ORDER BY id")).isEqualTo(after1);
        assertThat(count("velero-objectstore")).isEqualTo(1);
    }

    @Test
    void isANoOp_onTheExpectedEmptyLedger() throws Exception {
        apply(CL_350);
        Long rows = jdbc.queryForObject("SELECT COUNT(*) FROM backing_service_mode", Long.class);
        assertThat(rows).isZero();
        Long ran = jdbc.queryForObject("SELECT COUNT(*) FROM DATABASECHANGELOG WHERE ID = ?",
                Long.class, "350-backing-service-id-velero-objectstore");
        assertThat(ran).isEqualTo(1L);
    }

    @Test
    void masterChangelog_includes350_after310() throws Exception {
        String master;
        try (InputStream in = getClass().getResourceAsStream("/db/changelog/db.changelog-master.xml")) {
            assertThat(in).isNotNull();
            master = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        String inc310 = "<include file=\"db/changelog/310-backing-service-mode.xml\"/>";
        String inc350 = "<include file=\"db/changelog/350-backing-service-id-velero-objectstore.xml\"/>";
        assertThat(master).contains(inc310).contains(inc350);
        assertThat(master.indexOf(inc350)).as("350 must run after the 310 table exists")
                .isGreaterThan(master.indexOf(inc310));
    }
}
