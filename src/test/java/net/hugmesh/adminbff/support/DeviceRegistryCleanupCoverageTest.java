package net.hugmesh.adminbff.support;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.desktop.DesktopSudoGrantR2dbcRepository;
import net.hugmesh.adminbff.desktop.DesktopSudoGrantRow;
import net.hugmesh.adminbff.device.DeviceRow;
import net.hugmesh.adminbff.device.DeviceRowRepository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Keeps {@link DeviceRegistryCleanup#BLOCKING_CHILDREN} honest against the REAL schema.
 *
 * <p>A hand-maintained list of FK children is a list that rots: the next migration to hang a
 * {@code NO ACTION} table off {@code device_registry} would reintroduce the exact 38-error
 * full-suite failure this list was written to end, and it would do so silently — the suite
 * would pass in isolation and fail only in whichever ordering happened to leave a child row.
 *
 * <p>So the list is not trusted. This test asks Postgres which children actually block a
 * delete and asserts the constant matches <em>exactly</em>: a new blocking child fails here,
 * by name, with the line to add. A child that gains {@code ON DELETE CASCADE} (or disappears)
 * fails too, so the list cannot silently over-delete either.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, DeviceRegistryCleanupConfig.class})
@ActiveProfiles("test")
class DeviceRegistryCleanupCoverageTest {

    /**
     * The ONE place raw SQL is unavoidable: this interrogates {@code information_schema} for
     * foreign-key metadata, which no entity repository can express. Everything that touches
     * application tables goes through the Spring Data reactive repositories.
     */
    @Autowired DatabaseClient db;

    @Autowired DeviceRegistryCleanup deviceRegistryCleanup;
    @Autowired DeviceRowRepository devices;
    @Autowired DesktopSudoGrantR2dbcRepository sudoGrants;

    /**
     * Every FK pointing at {@code device_registry}, with the delete rule the database will
     * actually enforce. {@code constraint_column_usage} resolves to the REFERENCED table for a
     * foreign key, which is what makes this a "who points at me" query.
     */
    private static final String FK_CHILDREN = """
            SELECT tc.table_name AS child, rc.delete_rule AS rule
              FROM information_schema.table_constraints tc
              JOIN information_schema.referential_constraints rc
                ON rc.constraint_name   = tc.constraint_name
               AND rc.constraint_schema = tc.constraint_schema
              JOIN information_schema.constraint_column_usage ccu
                ON ccu.constraint_name   = tc.constraint_name
               AND ccu.constraint_schema = tc.constraint_schema
             WHERE tc.constraint_type = 'FOREIGN KEY'
               AND ccu.table_name     = 'device_registry'
            """;

    private List<Map<String, Object>> fkChildren() {
        return db.sql(FK_CHILDREN).fetch().all().collectList().block();
    }

    /**
     * ONE container serves every Spring context in the JVM, and the TestContext cache keeps
     * those contexts alive together, so their connections add up against a single server. At
     * Postgres's default of 100 the suite died with "FATAL: sorry, too many clients already"
     * in whichever context initialised last — which reads like a Liquibase failure and is
     * really just the ceiling.
     *
     * <p>Asserted rather than assumed because the obvious way to raise it does NOT work:
     * {@code PostgreSQLContainer.configure()} calls {@code setCommand()} itself and runs during
     * {@code start()}, so a plain {@code withCommand(...)} is silently overwritten. Without
     * this check that regression is invisible until the suite mysteriously goes red again.
     */
    @Test
    void theSharedContainerRaisedItsConnectionCeiling() {
        Integer maxConnections = db.sql("SHOW max_connections")
                .map(r -> Integer.valueOf(String.valueOf(r.get(0))))
                .one().block();
        assertThat(maxConnections)
                .as("max_connections did not reach Postgres — see TestDatabaseConfig.configure()")
                .isGreaterThan(100);
    }

    @Test
    void blockingChildrenList_matchesTheLiveSchema() {
        List<Map<String, Object>> rows = fkChildren();
        assertThat(rows).as("no FK to device_registry found — the query or the schema moved").isNotEmpty();

        Set<String> blockingInDb = rows.stream()
                .filter(r -> {
                    String rule = String.valueOf(r.get("rule")).toUpperCase();
                    return rule.equals("NO ACTION") || rule.equals("RESTRICT");
                })
                .map(r -> String.valueOf(r.get("child")))
                .collect(Collectors.toCollection(TreeSet::new));

        assertThat(blockingInDb)
                .as("""
                        DeviceRegistryCleanup.BLOCKING_CHILDREN has drifted from the schema.
                        Every table listed here blocks `DELETE FROM device_registry`, so a fixture
                        that does not clear it first will fail — but ONLY in a full-suite run where
                        an earlier class left a row, which is why this is asserted and not assumed.
                        Add or remove the named table in DeviceRegistryCleanup.BLOCKING_CHILDREN.""")
                .containsExactlyInAnyOrderElementsOf(DeviceRegistryCleanup.BLOCKING_CHILDREN);
    }

    @Test
    void cascadingChildren_areDeliberatelyNotInTheList() {
        Set<String> cascading = fkChildren().stream()
                .filter(r -> String.valueOf(r.get("rule")).equalsIgnoreCase("CASCADE"))
                .map(r -> String.valueOf(r.get("child")))
                .collect(Collectors.toCollection(TreeSet::new));

        assertThat(cascading)
                .as("a CASCADE child needs no manual delete; listing it would hide which FKs actually constrain the parent")
                .isNotEmpty()
                .doesNotContainAnyElementsOf(DeviceRegistryCleanup.BLOCKING_CHILDREN);
    }

    @Test
    void clearDeviceRegistry_survivesALeftoverGrantRow() {
        // The exact pollution that produced the 38 errors: a child row outliving its test.
        deviceRegistryCleanup.clearDeviceRegistry().block();

        // Values must satisfy the CHECK constraints: image_type IN (primary, mesh-extension,
        // client), owner_type IN (SUPERADMIN, ADMIN), grant state IN (active, revoked),
        // propagation_state IN (pending, applied, failed, degraded).
        devices.save(new DeviceRow("dev-fkfix", "fp-fkfix", "fkfix.example", null, "client",
                null, "ADMIN", "someone@brandx.example", "brandx", "mesh-fkfix",
                Instant.now(), null, true)).block();
        sudoGrants.save(new DesktopSudoGrantRow("grant-fkfix", "someone@brandx.example", "dev-fkfix",
                "active", "admin@brandx.example", Instant.now(), null, null, "brandx",
                "pending", 1L, true)).block();

        // Before the fix this threw DataIntegrityViolation on fk_desktop_sudo_grant_device.
        deviceRegistryCleanup.clearDeviceRegistry().block();

        assertThat(devices.count().block())
                .as("device_registry must be empty after an FK-safe clear").isZero();
        assertThat(sudoGrants.count().block())
                .as("the blocking child must have been cleared first, not left behind").isZero();
    }
}
