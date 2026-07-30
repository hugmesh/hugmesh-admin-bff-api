package systems.hugmesh.adminbff.device;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link DeviceRegistryService} over a Liquibase-applied H2 (PG-compat) — proves the 011
 * changelog applies (device_registry + CHECK constraints) and the FIX-NODEFAULT register
 * guard + idempotency. Mirrors {@code DomainLockRepositoryTest} wiring.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DeviceRegistryServiceTest {

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM device_ssh_license").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
    }

    /** A genuinely multi-issuer registry (two brands) — the normal register path. */
    private static final DomainRegistry MULTI = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
    /** Single-issuer registry — register REFUSES unless allow-single-issuer. */
    private static final DomainRegistry SINGLE = new DomainRegistry("https://id.example", "");

    /** Uses the 3-arg convenience constructor → headscale re-validation OFF (the ships-dark
     *  default): register accepts the supplied fp as-is, so these FIX-NODEFAULT / idempotency
     *  tests are unaffected by the AUTO-CAPTURE feature. The headscale-enabled re-validate
     *  path is covered in {@link DeviceRegistryHeadscaleRevalidateTest}. */
    private DeviceRegistryService svc(DomainRegistry registry, boolean allowSingle) {
        return new DeviceRegistryService(new DeviceRegistryRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.device.DeviceRowRepository.class)), registry, allowSingle);
    }

    private static Device device(String fp, String domain) {
        return new Device(null, fp, "node-" + fp, "tn", Device.IMAGE_MESH_EXTENSION, "rpi5",
                Device.OWNER_ADMIN, "alice@" + domain, domain, "mesh-1", null, null);
    }

    @Test
    void register_multiIssuer_nonDefaultDomain_succeeds() {
        DeviceRegistryService svc = svc(MULTI, false);
        Device saved = svc.register(device("fp-1", "brandx")).block();
        assertThat(saved).isNotNull();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.domain()).isEqualTo("brandx");
    }

    @Test
    void register_isIdempotentOnMachineKey() {
        DeviceRegistryService svc = svc(MULTI, false);
        Device first = svc.register(device("fp-dup", "brandx")).block();
        Device again = svc.register(device("fp-dup", "brandx")).block();
        // Same row returned (no UNIQUE violation) — the registry is keyed on machine_key_fp.
        assertThat(again.id()).isEqualTo(first.id());
        Long count = db.sql("SELECT COUNT(*) AS c FROM device_registry WHERE machine_key_fp = 'fp-dup'")
                .map((r, m) -> r.get("c", Long.class)).first().block();
        assertThat(count).isEqualTo(1L);
    }

    @Test
    void register_rejectsDefaultDomain_evenMultiIssuer() {
        DeviceRegistryService svc = svc(MULTI, false);
        // FIX-NODEFAULT: a 'default' residency would make the cross-domain wall vacuous.
        assertThatThrownBy(() -> svc.register(device("fp-2", "default")).block())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("default");
    }

    @Test
    void register_refusesSingleIssuer_unlessAllowed() {
        // Single-issuer: refused outright (per-domain SSH boundary cannot be drawn).
        DeviceRegistryService refusing = svc(SINGLE, false);
        assertThatThrownBy(() -> refusing.register(device("fp-3", "brandx")).block())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("multi-issuer");

        // ... unless the explicit single-issuer footgun override is set (and the domain
        // is still not 'default').
        DeviceRegistryService allowing = svc(SINGLE, true);
        Device saved = allowing.register(device("fp-4", "brandx")).block();
        assertThat(saved).isNotNull();
        assertThat(saved.domain()).isEqualTo("brandx");
    }

    @Test
    void imageTypeCheckConstraint_rejectsUnknownImageType() {
        // The DB CHECK (ck_device_registry_image_type) rejects a value outside the closed
        // vocabulary — a non-service write path cannot persist a bad row.
        Long updated = db.sql(
                        "INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, "
                        + " domain, mesh_id, created_at) "
                        + "VALUES ('x', 'fp', 'h', 'bogus', 'ADMIN', 'a', 'brandx', 'mesh-1', now())")
                .fetch().rowsUpdated().onErrorReturn(-1L).block();
        assertThat(updated).isEqualTo(-1L);
    }

    @Test
    void ownerTypeCheckConstraint_rejectsUnknownOwnerType() {
        Long updated = db.sql(
                        "INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, "
                        + " domain, mesh_id, created_at) "
                        + "VALUES ('y', 'fp2', 'h', 'mesh-extension', 'ROOT', 'a', 'brandx', 'mesh-1', now())")
                .fetch().rowsUpdated().onErrorReturn(-1L).block();
        assertThat(updated).isEqualTo(-1L);
    }

    @SuppressWarnings("unused")
    private static Instant now() { return Instant.now(); }
}
