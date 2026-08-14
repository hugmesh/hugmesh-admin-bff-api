package net.hugmesh.adminbff.phone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The {@link PhoneManagementService} state machine end-to-end over the real Liquibase Postgres,
 * with the real {@link DefaultPhoneLockEnforcer} wired to the DEFAULT (both-off) no-op legs —
 * so every lock/unlock records DEGRADED, exactly the shipping posture. Proves:
 * <ul>
 *   <li>lock a mesh_owned device &rarr; locked, generation 1, propagation degraded (both legs
 *       off), reason/actor stamped;</li>
 *   <li>unlock &rarr; generation 2 (monotonic); re-lock &rarr; generation 3;</li>
 *   <li><b>a BYOD (unmanaged) lock is a clean 409 and the state is UNCHANGED</b> (the core
 *       security assertion);</li>
 *   <li>clearing a LOCKED managed device to unmanaged auto-unlocks it (no locked orphan);</li>
 *   <li>an unknown device id is a 404 on every mutation.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class PhoneManagementServiceTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM phone_device").fetch().rowsUpdated().block();
    }

    private PhoneDeviceRepository repo() {
        return new PhoneDeviceRepository(net.hugmesh.adminbff.testutil.R2dbcRepos
                .of(db, PhoneDeviceRowRepository.class));
    }

    /** The service wired to the DEFAULT both-off no-op enforcement legs (ships dark). */
    private PhoneManagementService service(PhoneDeviceRepository repo) {
        PhoneLockEnforcer enforcer = new DefaultPhoneLockEnforcer(
                List.of(new NoopHeadwindDpcLockClient(), new NoopPhoneMeshDenyClient()));
        return new PhoneManagementService(repo, enforcer);
    }

    private void seed(PhoneDeviceRepository repo, String deviceId) {
        repo.upsert(new PhoneIngest(deviceId, "phone", "SER", "oriole", "Pixel 6",
                "GrapheneOS", "2026071400", "hugmesh.internal", "https://hs.internal",
                "100.64.0.7", "phone-host", "user", "acme.hugmesh.net", true, 10L,
                "vault-seed", true, "com.hmdm.launcher", "https://headwind.internal",
                "adb-device-owner", Instant.parse("2026-07-14T11:58:00Z"),
                "https://attest", "auditor", "operator-paired",
                Instant.parse("2026-07-14T12:00:00Z"), Instant.parse("2026-07-14T12:05:00Z"),
                "headwind", null))
                .block();
    }

    @Test
    void lock_managed_locksBumpsGenerationRecordsDegraded() {
        PhoneDeviceRepository repo = repo();
        PhoneManagementService service = service(repo);
        seed(repo, "phone-m");
        service.setManagementMode("phone-m", "mesh_owned", "sa-op").block();

        PhoneDevice locked = service.lock("phone-m", "reported stolen", "sa-op").block();
        assertThat(locked).isNotNull();
        assertThat(locked.lockState()).isEqualTo("locked");
        assertThat(locked.lockGeneration()).isEqualTo(1L);
        assertThat(locked.lockReason()).isEqualTo("reported stolen");
        assertThat(locked.lockActor()).isEqualTo("sa-op");
        assertThat(locked.lockUpdatedAt()).isNotNull();
        // Both enforcement legs are off (the default) -> the enforcement DEGRADED, but the
        // control-plane lock is authoritative regardless.
        assertThat(locked.lockPropagationState()).isEqualTo("degraded");
    }

    @Test
    void lockUnlockReLock_generationMonotonic() {
        PhoneDeviceRepository repo = repo();
        PhoneManagementService service = service(repo);
        seed(repo, "phone-g");
        service.setManagementMode("phone-g", "mesh_owned", "sa").block();

        assertThat(service.lock("phone-g", "a", "sa").block().lockGeneration()).isEqualTo(1L);
        assertThat(service.unlock("phone-g", "sa").block().lockGeneration()).isEqualTo(2L);
        assertThat(service.lock("phone-g", "b", "sa").block().lockGeneration()).isEqualTo(3L);
    }

    @Test
    void byodLock_is409_andLeavesStateUnchanged() {
        PhoneDeviceRepository repo = repo();
        PhoneManagementService service = service(repo);
        seed(repo, "phone-byod");                                // unmanaged by default

        Throwable ex = org.assertj.core.api.Assertions.catchThrowable(
                () -> service.lock("phone-byod", "attempt", "sa").block());
        assertThat(ex).isInstanceOf(ApiException.class);
        assertThat(((ApiException) ex).status()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(ex).hasMessageContaining("is not a managed device");

        // The state is completely untouched — no lock, no generation bump, no partial write.
        PhoneDevice d = repo.findByDeviceId("phone-byod").block();
        assertThat(d.managementMode()).isEqualTo("unmanaged");
        assertThat(d.lockState()).isEqualTo("unlocked");
        assertThat(d.lockGeneration()).isEqualTo(0L);
        assertThat(d.lockPropagationState()).isNull();
    }

    @Test
    void clearManaged_whileLocked_autoUnlocks() {
        PhoneDeviceRepository repo = repo();
        PhoneManagementService service = service(repo);
        seed(repo, "phone-clear");
        service.setManagementMode("phone-clear", "mesh_owned", "sa").block();
        service.lock("phone-clear", "why", "sa").block();        // locked, gen 1

        PhoneDevice cleared = service.setManagementMode("phone-clear", "unmanaged", "sa").block();
        assertThat(cleared.managementMode()).isEqualTo("unmanaged");
        assertThat(cleared.lockState()).isEqualTo("unlocked");   // no locked orphan
        assertThat(cleared.lockGeneration()).isEqualTo(2L);      // the auto-unlock bumped it
    }

    @Test
    void setManagementMode_roundTrips_managedThenBackToBYOD() {
        PhoneDeviceRepository repo = repo();
        PhoneManagementService service = service(repo);
        seed(repo, "phone-rt");
        assertThat(service.setManagementMode("phone-rt", "mesh_owned", "sa").block().isManaged()).isTrue();
        // Clearing an UNLOCKED managed device is a plain mode set (no unlock path).
        PhoneDevice back = service.setManagementMode("phone-rt", "unmanaged", "sa").block();
        assertThat(back.managementMode()).isEqualTo("unmanaged");
        assertThat(back.lockState()).isEqualTo("unlocked");
    }

    @Test
    void unknownDevice_is404_onEveryMutation() {
        PhoneManagementService service = service(repo());
        for (var call : List.<Runnable>of(
                () -> service.setManagementMode("nope", "mesh_owned", "sa").block(),
                () -> service.lock("nope", "r", "sa").block(),
                () -> service.unlock("nope", "sa").block())) {
            assertThatThrownBy(call::run)
                    .isInstanceOf(ApiException.class)
                    .satisfies(e -> assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.NOT_FOUND));
        }
    }

    /**
     * The enforcement leg must receive the device carrying the POST-bump generation, not the
     * stale pre-read one — a real (flag-enabled) leg stamps that generation into the wire
     * command a downstream store uses for rollback rejection, so an off-by-one silently drops
     * the first-ever lock (payload gen 0 vs authoritative row gen 1). Capture what the leg saw.
     */
    @Test
    void enforcementLeg_seesPostBumpGeneration() {
        PhoneDeviceRepository repo = repo();
        var capture = new java.util.ArrayList<Long>();
        PhoneLockLeg capturing = new PhoneLockLeg() {
            @Override public String name() { return "capture"; }
            @Override public reactor.core.publisher.Mono<PhoneLockLeg.LegOutcome> lock(PhoneDevice d) {
                capture.add(d.lockGeneration());
                return reactor.core.publisher.Mono.just(PhoneLockLeg.LegOutcome.applied());
            }
            @Override public reactor.core.publisher.Mono<PhoneLockLeg.LegOutcome> unlock(PhoneDevice d) {
                capture.add(d.lockGeneration());
                return reactor.core.publisher.Mono.just(PhoneLockLeg.LegOutcome.applied());
            }
        };
        PhoneManagementService service =
                new PhoneManagementService(repo, new DefaultPhoneLockEnforcer(List.of(capturing)));
        seed(repo, "phone-gen");
        service.setManagementMode("phone-gen", "mesh_owned", "sa").block();

        service.lock("phone-gen", "r", "sa").block();     // row -> generation 1
        service.unlock("phone-gen", "sa").block();        // row -> generation 2
        // The leg saw exactly the bumped generations the authoritative row holds, in order —
        // never the pre-bump 0.
        assertThat(capture).containsExactly(1L, 2L);
    }

    // ── changeset-305 owner-scoped fleet-admin path (setOwner + lockOwned/unlockOwned) ─

    private static final String ALICE = "alice-subject";
    private static final String BOB = "bob-subject";
    private static final String ACME = "acme.hugmesh.net";
    private static final String BETA = "beta.hugmesh.net";

    @Test
    void setOwner_assignsOwnerAndDomain_leavesManagementUntouched() {
        PhoneDeviceRepository repo = repo();
        PhoneManagementService service = service(repo);
        seed(repo, "phone-o");

        PhoneDevice owned = service.setOwner("phone-o", ALICE, ACME, "sa").block();
        assertThat(owned).isNotNull();
        assertThat(owned.physicalOwner()).isEqualTo(ALICE);
        assertThat(owned.ownerDomain()).isEqualTo(ACME);
        assertThat(owned.managementMode()).isEqualTo("unmanaged");   // owner assignment is orthogonal
        assertThat(owned.lockState()).isEqualTo("unlocked");
    }

    @Test
    void setOwner_unknownDevice_is404() {
        PhoneManagementService service = service(repo());
        assertThatThrownBy(() -> service.setOwner("nope", ALICE, ACME, "sa").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.NOT_FOUND));
    }

    @Test
    void lockOwned_ownedManaged_locks_andBumpsGeneration() {
        PhoneDeviceRepository repo = repo();
        PhoneManagementService service = service(repo);
        seed(repo, "phone-om");
        service.setOwner("phone-om", ALICE, ACME, "sa").block();
        service.setManagementMode("phone-om", "mesh_owned", "sa").block();

        PhoneDevice locked = service.lockOwned("phone-om", "stolen", "alice-op", ALICE, ACME).block();
        assertThat(locked).isNotNull();
        assertThat(locked.lockState()).isEqualTo("locked");
        assertThat(locked.lockGeneration()).isEqualTo(1L);
        assertThat(locked.lockReason()).isEqualTo("stolen");

        PhoneDevice unlocked = service.unlockOwned("phone-om", "alice-op", ALICE, ACME).block();
        assertThat(unlocked.lockState()).isEqualTo("unlocked");
        assertThat(unlocked.lockGeneration()).isEqualTo(2L);       // monotonic
    }

    @Test
    void lockOwned_crossOwnerOrCrossDomain_is404_beforeAnyLockLogic() {
        PhoneDeviceRepository repo = repo();
        PhoneManagementService service = service(repo);
        seed(repo, "phone-x");
        service.setOwner("phone-x", ALICE, ACME, "sa").block();
        service.setManagementMode("phone-x", "mesh_owned", "sa").block();

        // Another owner — a clean 404 (indistinguishable from unknown; no enumeration).
        assertThatThrownBy(() -> service.lockOwned("phone-x", "r", "bob-op", BOB, ACME).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.NOT_FOUND));
        // Same owner, wrong domain — also 404 (proves the domain predicate, not just owner).
        assertThatThrownBy(() -> service.lockOwned("phone-x", "r", "alice-op", ALICE, BETA).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.NOT_FOUND));

        // The device stayed unlocked throughout — no cross-owner lock ever took.
        assertThat(repo.findByDeviceId("phone-x").block().lockState()).isEqualTo("unlocked");
    }

    @Test
    void lockOwned_ownedButBYOD_is409() {
        PhoneDeviceRepository repo = repo();
        PhoneManagementService service = service(repo);
        seed(repo, "phone-byod");
        service.setOwner("phone-byod", ALICE, ACME, "sa").block();   // owned but UNMANAGED

        assertThatThrownBy(() -> service.lockOwned("phone-byod", "r", "alice-op", ALICE, ACME).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.CONFLICT))
                .hasMessageContaining("is not a managed device");
        assertThat(repo.findByDeviceId("phone-byod").block().lockState()).isEqualTo("unlocked");
    }

    @Test
    void unlockOwned_crossOwner_is404() {
        PhoneDeviceRepository repo = repo();
        PhoneManagementService service = service(repo);
        seed(repo, "phone-u");
        service.setOwner("phone-u", ALICE, ACME, "sa").block();
        service.setManagementMode("phone-u", "mesh_owned", "sa").block();
        service.lockOwned("phone-u", "stolen", "alice-op", ALICE, ACME).block();

        assertThatThrownBy(() -> service.unlockOwned("phone-u", "bob-op", BOB, ACME).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.NOT_FOUND));
        // The cross-owner unlock never landed — still locked.
        assertThat(repo.findByDeviceId("phone-u").block().lockState()).isEqualTo("locked");
    }
}
