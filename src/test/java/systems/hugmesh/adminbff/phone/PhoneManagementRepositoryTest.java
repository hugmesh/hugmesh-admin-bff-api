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
 * The changeset-304 management + lockout CAS state machine over the real Liquibase-applied
 * Postgres — the DB half of the contract (every assertion reads the STORE, never an echo):
 * <ul>
 *   <li>the 304 columns apply with the right DEFAULTs (a fresh ingest is
 *       unmanaged/unlocked/generation 0);</li>
 *   <li>lock is CAS-guarded on management_mode='mesh_owned' — a BYOD lock matches NO row
 *       (the DB-level half of the 409) and leaves the state untouched;</li>
 *   <li>lock/unlock bump the MONOTONIC per-device generation (1, 2, 3 …) and stamp
 *       reason/actor/updated_at + propagation pending;</li>
 *   <li>clear-managed-and-unlock is guarded on lock_state='locked' (no locked orphan);</li>
 *   <li>the propagation update is generation-guarded (a stale result never clobbers a newer
 *       lock);</li>
 *   <li>a re-ingest (UPSERT REFRESH) preserves EVERY operator-state column while refreshing
 *       telemetry — the trust boundary.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class PhoneManagementRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM phone_device").fetch().rowsUpdated().block();
    }

    private PhoneDeviceRepository repo() {
        return new PhoneDeviceRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos
                .of(db, PhoneDeviceRowRepository.class));
    }

    private static PhoneIngest ingest(String deviceId) {
        return new PhoneIngest(deviceId, "phone", "1C291FDF3005A", "oriole", "Pixel 6",
                "GrapheneOS", "2026071400", "hugmesh.internal",
                "https://headscale.hugmesh.internal", "100.64.0.7", "phone-hostname",
                "user", "acme.hugmesh.systems", true, 10L, "vault-seed",
                true, "com.hmdm.launcher", "https://headwind.hugmesh.internal",
                "adb-device-owner", Instant.parse("2026-07-14T11:58:00Z"),
                "https://attestation.hugmesh.systems", "systems.hugmesh.auditor",
                "operator-paired", Instant.parse("2026-07-14T12:00:00Z"),
                Instant.parse("2026-07-14T12:05:00Z"), "headwind", null);
    }

    /** A telemetry-changed re-ingest of the SAME device_id (serial/os/hostname differ). */
    private static PhoneIngest reIngest(String deviceId) {
        return new PhoneIngest(deviceId, "phone", "NEWSERIAL", "raven", "Pixel 6 Pro",
                "unknown", "2026081500", "other.internal", "https://hs2.internal",
                "100.64.9.9", "phone-renamed", "admin", "beta.hugmesh.systems",
                false, null, null, false, null, null, null, null, null, null, null, null, null,
                "headwind", null);
    }

    @Test
    void freshIngest_defaultsUnmanagedUnlockedGenerationZero() {
        repo().upsert(ingest("phone-a")).block();
        PhoneDevice d = repo().findByDeviceId("phone-a").block();
        assertThat(d).isNotNull();
        assertThat(d.managementMode()).isEqualTo("unmanaged");
        assertThat(d.lockState()).isEqualTo("unlocked");
        assertThat(d.lockPropagationState()).isNull();
        assertThat(d.lockGeneration()).isEqualTo(0L);
        assertThat(d.lockReason()).isNull();
        assertThat(d.lockActor()).isNull();
        assertThat(d.lockUpdatedAt()).isNull();
        assertThat(d.isManaged()).isFalse();
        assertThat(d.isLocked()).isFalse();
    }

    @Test
    void byodLock_matchesNoRow_stateUnchanged() {
        PhoneDeviceRepository repo = repo();
        repo.upsert(ingest("phone-byod")).block();               // unmanaged by default
        Long gen = repo.lockManaged("phone-byod", "attempt", "sa").block();
        assertThat(gen).isNull();                                // CAS guard: NO row matched
        PhoneDevice d = repo.findByDeviceId("phone-byod").block();
        assertThat(d.lockState()).isEqualTo("unlocked");         // untouched
        assertThat(d.lockGeneration()).isEqualTo(0L);
    }

    @Test
    void managedLock_thenUnlock_thenReLock_generationMonotonic() {
        PhoneDeviceRepository repo = repo();
        repo.upsert(ingest("phone-m")).block();
        repo.setManagementMode("phone-m", "mesh_owned").block();

        Long g1 = repo.lockManaged("phone-m", "stolen", "sa-1").block();
        assertThat(g1).isEqualTo(1L);
        PhoneDevice locked = repo.findByDeviceId("phone-m").block();
        assertThat(locked.lockState()).isEqualTo("locked");
        assertThat(locked.lockPropagationState()).isEqualTo("pending");
        assertThat(locked.lockReason()).isEqualTo("stolen");
        assertThat(locked.lockActor()).isEqualTo("sa-1");
        assertThat(locked.lockUpdatedAt()).isNotNull();

        Long g2 = repo.unlock("phone-m", "sa-2").block();
        assertThat(g2).isEqualTo(2L);                            // MONOTONIC across unlock
        PhoneDevice unlocked = repo.findByDeviceId("phone-m").block();
        assertThat(unlocked.lockState()).isEqualTo("unlocked");
        assertThat(unlocked.lockReason()).isNull();              // cleared on unlock
        assertThat(unlocked.lockActor()).isEqualTo("sa-2");

        Long g3 = repo.lockManaged("phone-m", "again", "sa-3").block();
        assertThat(g3).isEqualTo(3L);                            // keeps climbing
    }

    @Test
    void clearManagedAndUnlock_onlyFiresWhenLocked() {
        PhoneDeviceRepository repo = repo();
        repo.upsert(ingest("phone-c")).block();
        repo.setManagementMode("phone-c", "mesh_owned").block();
        // Not locked yet -> the guarded clear matches nothing.
        assertThat(repo.clearManagedAndUnlock("phone-c", "sa").block()).isNull();

        repo.lockManaged("phone-c", "why", "sa").block();        // gen 1, locked
        Long gen = repo.clearManagedAndUnlock("phone-c", "sa").block();
        assertThat(gen).isEqualTo(2L);                           // unlock bump
        PhoneDevice d = repo.findByDeviceId("phone-c").block();
        assertThat(d.managementMode()).isEqualTo("unmanaged");   // cleared
        assertThat(d.lockState()).isEqualTo("unlocked");         // no locked orphan
    }

    @Test
    void updateLockPropagation_isGenerationGuarded() {
        PhoneDeviceRepository repo = repo();
        repo.upsert(ingest("phone-p")).block();
        repo.setManagementMode("phone-p", "mesh_owned").block();
        long gen = repo.lockManaged("phone-p", "x", "sa").block();   // gen 1, pending

        // Recording the outcome for the CURRENT generation lands.
        assertThat(repo.updateLockPropagation("phone-p", gen, "applied").block()).isEqualTo(1L);
        assertThat(repo.findByDeviceId("phone-p").block().lockPropagationState()).isEqualTo("applied");

        // A STALE generation's result is rejected (0 rows) — never clobbers the newer state.
        assertThat(repo.updateLockPropagation("phone-p", gen - 1, "failed").block()).isEqualTo(0L);
        assertThat(repo.findByDeviceId("phone-p").block().lockPropagationState()).isEqualTo("applied");
    }

    @Test
    void reIngest_preservesOperatorState_refreshesTelemetry() {
        PhoneDeviceRepository repo = repo();
        repo.upsert(ingest("phone-r")).block();
        repo.setManagementMode("phone-r", "mesh_owned").block();
        repo.lockManaged("phone-r", "seized", "sa-op").block();  // managed + locked, gen 1

        // A spoofable re-ingest (the wizard re-run) refreshes telemetry but must NOT touch
        // operator state — the whole point of the trust boundary.
        repo.upsert(reIngest("phone-r")).block();
        PhoneDevice d = repo.findByDeviceId("phone-r").block();
        // Operator state preserved.
        assertThat(d.managementMode()).isEqualTo("mesh_owned");
        assertThat(d.lockState()).isEqualTo("locked");
        assertThat(d.lockGeneration()).isEqualTo(1L);
        assertThat(d.lockReason()).isEqualTo("seized");
        assertThat(d.lockActor()).isEqualTo("sa-op");
        // Telemetry refreshed + counter bumped.
        assertThat(d.serial()).isEqualTo("NEWSERIAL");
        assertThat(d.os()).isEqualTo("unknown");
        assertThat(d.tailscaleHostname()).isEqualTo("phone-renamed");
        assertThat(d.ingestCount()).isEqualTo(2L);
    }
}
