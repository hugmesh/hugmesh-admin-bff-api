package systems.hugmesh.adminbff.phone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The CHANGESET-307 provider telemetry meets the WAVE-1 (304/305) operator-state trust boundary,
 * over the real Liquibase-applied Postgres (every assertion reads the STORE). The individual
 * halves are already netted:
 * <ul>
 *   <li>{@link PhoneDeviceRepositoryTest} proves the {@code mdm_provider}/{@code intune_device_id}
 *       round-trip AND a re-ingest FLIP (headwind &rarr; azure-intune);</li>
 *   <li>{@link PhoneManagementRepositoryTest} proves a re-ingest preserves management/lock state;</li>
 *   <li>{@link PhoneFleetOwnerRepositoryTest} proves a re-ingest preserves the owner columns.</li>
 * </ul>
 *
 * <p>What NONE of them assert — and what this adds — is the COMBINED invariant in ONE hostile
 * re-ingest: the device-reported provider is telemetry that legitimately CHANGES on a re-ingest
 * (the wizard re-enrolled the phone with Azure Intune), and in the SAME UPSERT the whole wave-1
 * operator state — {@code physical_owner}, {@code owner_domain}, {@code management_mode} AND the
 * {@code lock_*} columns — MUST survive untouched. A REFRESH SQL that widened its SET list to
 * sweep in an operator column while updating the 307 provider columns would land here (a hostile
 * ingest could then flip a locked, owned device's owner or clear its lock) — exactly the boundary
 * the spoofable ingest channel must never cross.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class PhoneIngestProviderRoundTripTest {

    private static final String OWNER = "owner-subject";
    private static final String DOMAIN = "acme.hugmesh.systems";

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM phone_device").fetch().rowsUpdated().block();
    }

    private PhoneDeviceRepository repo() {
        return new PhoneDeviceRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos
                .of(db, PhoneDeviceRowRepository.class));
    }

    /** First ingest: a Headwind device, no Intune id. */
    private static PhoneIngest headwindIngest(String deviceId) {
        return new PhoneIngest(deviceId, "phone", "SER-1", "oriole", "Pixel 6", "GrapheneOS",
                "2026071400", "hugmesh.internal", "https://hs.internal", "100.64.0.7",
                "phone-host", "user", "acme.hugmesh.systems", true, 10L, "vault-seed",
                true, "com.hmdm.launcher", "https://headwind.internal", "adb-device-owner",
                Instant.parse("2026-07-14T11:58:00Z"), "https://attest", "auditor",
                "operator-paired", Instant.parse("2026-07-14T12:00:00Z"),
                Instant.parse("2026-07-14T12:05:00Z"), "headwind", null);
    }

    /** A HOSTILE re-ingest of the same device_id: provider FLIPPED to azure-intune (+ a Graph
     *  device id) and telemetry changed — everything the spoofable channel is ALLOWED to change,
     *  and nothing it is not (no owner/mode/lock fields exist on PhoneIngest at all). */
    private static PhoneIngest azureReIngest(String deviceId) {
        return new PhoneIngest(deviceId, "phone", "SER-2", "raven", "Pixel 6 Pro", "unknown",
                "2026081500", "other.internal", "https://hs2.internal", "100.64.9.9",
                "phone-renamed", "admin", "beta.hugmesh.systems", false, null, null,
                false, "com.other.dpc", "https://headwind2.internal", "qr-provisioning",
                Instant.parse("2026-08-15T00:58:00Z"), "https://attest2", "auditor2",
                "failed", Instant.parse("2026-08-15T01:00:00Z"),
                Instant.parse("2026-08-15T01:05:00Z"), "azure-intune", "intune-dev-xyz");
    }

    @Test
    void hostileReIngest_flipsProviderTelemetry_butPreservesOwnerManagementAndLock() {
        PhoneDeviceRepository repo = repo();
        repo.upsert(headwindIngest("dev-1")).block();

        // Bring the device to a fully operator-provisioned, LOCKED state on the wave-1 planes.
        assertThat(repo.setOwner("dev-1", OWNER, DOMAIN).block()).isNotNull();
        repo.setManagementMode("dev-1", "mesh_owned").block();
        assertThat(repo.lockManaged("dev-1", "seized", "sa-op").block()).isEqualTo(1L);

        PhoneDevice before = repo.findByDeviceId("dev-1").block();
        assertThat(before.effectiveMdmProvider()).isEqualTo("headwind");
        assertThat(before.isManaged()).isTrue();
        assertThat(before.isLocked()).isTrue();

        // The hostile re-ingest: provider telemetry flips, operator state must NOT move.
        repo.upsert(azureReIngest("dev-1")).block();
        PhoneDevice after = repo.findByDeviceId("dev-1").block();

        // 307 device-reported provider telemetry legitimately CHANGED.
        assertThat(after.mdmProvider()).isEqualTo("azure-intune");
        assertThat(after.intuneDeviceId()).isEqualTo("intune-dev-xyz");
        // ...and ordinary telemetry refreshed + the ingest counter bumped.
        assertThat(after.serial()).isEqualTo("SER-2");
        assertThat(after.os()).isEqualTo("unknown");
        assertThat(after.tailscaleHostname()).isEqualTo("phone-renamed");
        assertThat(after.ingestCount()).isEqualTo(2L);

        // WAVE-1 OPERATOR STATE — every column UNTOUCHED by the spoofable channel.
        assertThat(after.physicalOwner()).isEqualTo(OWNER);
        assertThat(after.ownerDomain()).isEqualTo(DOMAIN);
        assertThat(after.managementMode()).isEqualTo("mesh_owned");
        assertThat(after.lockState()).isEqualTo("locked");
        assertThat(after.lockGeneration()).isEqualTo(1L);      // NOT bumped by ingest
        assertThat(after.lockReason()).isEqualTo("seized");
        assertThat(after.lockActor()).isEqualTo("sa-op");
    }
}
