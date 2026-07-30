package systems.hugmesh.adminbff.phone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;

/**
 * The SUPERADMIN control-plane write surface for phone MANAGEMENT + LOCKOUT (changeset 304) —
 * the authoritative counterpart to the read-only {@link PhoneDeviceService}. Every mutation is
 * a CAS transition against {@code phone_device} that bumps the MONOTONIC per-device
 * {@code lock_generation} and then runs best-effort enforcement, recording the push-with-ack
 * outcome. The DB row is ALWAYS authoritative: the enforcer never decides whether the lock
 * "took", only how far the side effect propagated.
 *
 * <h3>Trust boundary</h3>
 * {@code management_mode} is written ONLY here (reached only via {@code /bff/superadmin/**} +
 * step-up). The spoofable ingest channel writes it NEVER — {@link PhoneDeviceRowRepository}'s
 * INSERT/REFRESH omit all seven 304 columns — so a device cannot self-promote to managed and a
 * re-ingest cannot clear a lock.
 *
 * <h3>State machine (mirrors device_ssh_license)</h3>
 * <ul>
 *   <li>{@link #setManagementMode} — set the managed/BYOD discriminator. Clearing a LOCKED
 *       managed device to {@code unmanaged} ALSO unlocks it (no locked orphan), which itself
 *       bumps the generation + runs unlock enforcement.</li>
 *   <li>{@link #lock} — permitted ONLY on a {@code mesh_owned} device (a BYOD lock is a clean
 *       409). Sets locked, bumps generation, marks propagation pending, then enforces.</li>
 *   <li>{@link #unlock} — sets unlocked, bumps generation, marks propagation pending, then
 *       enforces. Generation stays monotonic across lock AND unlock.</li>
 * </ul>
 */
@Service
public class PhoneManagementService {

    private static final Logger log = LoggerFactory.getLogger(PhoneManagementService.class);

    private final PhoneDeviceRepository repo;
    private final PhoneLockEnforcer enforcer;

    public PhoneManagementService(PhoneDeviceRepository repo, PhoneLockEnforcer enforcer) {
        this.repo = repo;
        this.enforcer = enforcer;
    }

    /**
     * Set the authoritative {@code management_mode} ({@code mesh_owned} | {@code unmanaged}).
     * Unknown device_id &rarr; 404. Clearing a currently-LOCKED managed device to
     * {@code unmanaged} auto-unlocks it in one atomic step (no locked orphan), bumps the
     * generation and runs unlock enforcement; every other case is a plain mode set. Returns
     * the updated device.
     */
    public Mono<PhoneDevice> setManagementMode(String deviceId, String mode, String actor) {
        String normalized = normalizeMode(mode);
        return repo.findByDeviceId(deviceId)
                .switchIfEmpty(notFound(deviceId))
                .flatMap(device -> applyManagementMode(device, normalized, actor));
    }

    private Mono<PhoneDevice> applyManagementMode(PhoneDevice device, String mode, String actor) {
        // Clearing a LOCKED managed device -> unmanaged must ALSO unlock (a locked BYOD row
        // would be an unreachable orphan). The atomic clear-and-unlock is CAS-guarded on
        // lock_state='locked': it EMITS the new generation on a match (then enforce + reload),
        // and is EMPTY when a race already unlocked it — in which case switchIfEmpty falls back
        // to a plain mode set. reload() lives INSIDE the flatMap so the empty path is the ONLY
        // thing that reaches the fallback.
        if (PhoneDevice.MANAGEMENT_UNMANAGED.equals(mode) && device.isLocked()) {
            log.info("[phone-mgmt] clear-managed on LOCKED device by {} -> unmanaged + auto-unlock", actor);
            return repo.clearManagedAndUnlock(device.deviceId(), actor)
                    .flatMap(generation -> recordEnforcement(
                            enforcer.enforceUnlock(device.withLock(PhoneDevice.LOCK_UNLOCKED, generation)),
                            device.deviceId(), generation)
                            .then(reload(device.deviceId())))
                    .switchIfEmpty(Mono.defer(() -> plainSetMode(device.deviceId(), mode, actor)));
        }
        return plainSetMode(device.deviceId(), mode, actor);
    }

    private Mono<PhoneDevice> plainSetMode(String deviceId, String mode, String actor) {
        return repo.setManagementMode(deviceId, mode)
                .switchIfEmpty(PhoneManagementService.<Long>notFound(deviceId))
                .doOnNext(g -> log.info("[phone-mgmt] set management_mode={} on device by {}", mode, actor))
                .then(reload(deviceId));
    }

    /**
     * Lock a MANAGED device. Requires {@code management_mode='mesh_owned'} — a BYOD
     * (unmanaged) device is a clean 409 {@code "phone '<id>' is not a managed device"}, its
     * state UNCHANGED (the core security assertion). Sets locked, bumps the monotonic
     * generation, marks propagation pending, then runs enforcement and records the outcome.
     * Re-locking an already-locked managed device re-runs enforcement + bumps the generation.
     * Returns the updated device.
     */
    public Mono<PhoneDevice> lock(String deviceId, String reason, String actor) {
        return repo.findByDeviceId(deviceId)
                .switchIfEmpty(notFound(deviceId))
                .flatMap(device -> {
                    if (!device.isManaged()) {
                        return Mono.error(ApiException.conflict(
                                "phone '" + deviceId + "' is not a managed device"));
                    }
                    // CAS-guarded on mesh_owned: an empty emission means a race cleared the
                    // mode between the read and the write — still a 409, never a false lock.
                    return repo.lockManaged(deviceId, reason, actor)
                            .switchIfEmpty(Mono.error(ApiException.conflict(
                                    "phone '" + deviceId + "' is not a managed device")))
                            .flatMap(generation -> {
                                log.info("[phone-mgmt] LOCK device by {} gen={}", actor, generation);
                                return recordEnforcement(
                                        enforcer.enforceLock(device.withLock(PhoneDevice.LOCK_LOCKED, generation)),
                                        deviceId, generation);
                            })
                            .then(reload(deviceId));
                });
    }

    /**
     * Unlock a device: sets unlocked, bumps the monotonic generation, marks propagation
     * pending, then runs enforcement and records the outcome. Unknown device_id &rarr; 404.
     * Returns the updated device.
     */
    public Mono<PhoneDevice> unlock(String deviceId, String actor) {
        return repo.findByDeviceId(deviceId)
                .switchIfEmpty(notFound(deviceId))
                .flatMap(device -> repo.unlock(deviceId, actor)
                        .flatMap(generation -> {
                            log.info("[phone-mgmt] UNLOCK device by {} gen={}", actor, generation);
                            return recordEnforcement(
                                    enforcer.enforceUnlock(device.withLock(PhoneDevice.LOCK_UNLOCKED, generation)),
                                    deviceId, generation);
                        })
                        .then(reload(deviceId)));
    }

    /**
     * Set the AUTHORITATIVE fleet owner (physical_owner + owner_domain, changeset 305) —
     * SUPERADMIN plane only. Unknown device_id &rarr; 404. Does NOT touch management/lock
     * state (a re-owner is orthogonal to managed/locked status). Returns the updated device.
     */
    public Mono<PhoneDevice> setOwner(String deviceId, String physicalOwner, String ownerDomain,
                                      String actor) {
        return repo.setOwner(deviceId, physicalOwner, ownerDomain)
                .switchIfEmpty(PhoneManagementService.<Long>notFound(deviceId))
                .doOnNext(g -> log.info("[phone-mgmt] set owner + domain on device by {}", actor))
                .then(reload(deviceId));
    }

    /**
     * OWNER-SCOPED lock — the FLEET_ADMIN lock (changeset 305). The device is FIRST read
     * owner+domain-scoped, so a device the caller does not own (or one in another domain) is a
     * clean 404 BEFORE any lock logic (no enumeration; indistinguishable from unknown). An
     * OWNED BYOD device is a 409 (managed-only, exactly like the superadmin lock). The CAS is
     * itself owner+domain+mesh_owned-guarded, so even a race after the read can never lock a
     * cross-owner device (an empty emission is a 409, never a false lock). Returns the updated
     * device (re-read owner-scoped).
     */
    public Mono<PhoneDevice> lockOwned(String deviceId, String reason, String actor,
                                       String owner, String domain) {
        return repo.findByDeviceIdOwned(deviceId, owner, domain)
                .switchIfEmpty(notFound(deviceId))
                .flatMap(device -> {
                    if (!device.isManaged()) {
                        return Mono.error(ApiException.conflict(
                                "phone '" + deviceId + "' is not a managed device"));
                    }
                    return repo.lockManagedOwned(deviceId, reason, actor, owner, domain)
                            .switchIfEmpty(Mono.error(ApiException.conflict(
                                    "phone '" + deviceId + "' is not a managed device")))
                            .flatMap(generation -> {
                                log.info("[phone-fleet] LOCK owned device by {} gen={}", actor, generation);
                                return recordEnforcement(
                                        enforcer.enforceLock(device.withLock(PhoneDevice.LOCK_LOCKED, generation)),
                                        deviceId, generation);
                            })
                            .then(reloadOwned(deviceId, owner, domain));
                });
    }

    /**
     * OWNER-SCOPED unlock — the FLEET_ADMIN unlock (changeset 305). The device is FIRST read
     * owner+domain-scoped (404 when not owned-by-caller-in-domain); the CAS is owner+domain
     * guarded so a cross-owner unlock matches no row. Returns the updated device.
     */
    public Mono<PhoneDevice> unlockOwned(String deviceId, String actor, String owner, String domain) {
        return repo.findByDeviceIdOwned(deviceId, owner, domain)
                .switchIfEmpty(notFound(deviceId))
                .flatMap(device -> repo.unlockOwned(deviceId, actor, owner, domain)
                        .switchIfEmpty(PhoneManagementService.<Long>notFound(deviceId))
                        .flatMap(generation -> {
                            log.info("[phone-fleet] UNLOCK owned device by {} gen={}", actor, generation);
                            return recordEnforcement(
                                    enforcer.enforceUnlock(device.withLock(PhoneDevice.LOCK_UNLOCKED, generation)),
                                    deviceId, generation);
                        })
                        .then(reloadOwned(deviceId, owner, domain)));
    }

    /** Re-read the authoritative row owner-scoped for the fleet-admin response. */
    private Mono<PhoneDevice> reloadOwned(String deviceId, String owner, String domain) {
        return repo.findByDeviceIdOwned(deviceId, owner, domain);
    }

    /**
     * Run the (never-throwing) enforcement and stamp its outcome onto
     * {@code lock_propagation_state} for THIS generation (guarded so a newer lock/unlock is
     * never clobbered). The control-plane lock state is already authoritative regardless.
     */
    private Mono<Long> recordEnforcement(Mono<PhoneLockEnforcer.Outcome> enforcement,
                                         String deviceId, long generation) {
        return enforcement.flatMap(outcome ->
                repo.updateLockPropagation(deviceId, generation, outcome.propagationState())
                        .doOnNext(n -> log.info("[phone-mgmt] enforcement {} for device gen={} (reason={})",
                                outcome.propagationState(), generation, outcome.reason()))
                        .thenReturn(generation));
    }

    /** Re-read the authoritative row for the response (never an in-memory echo). */
    private Mono<PhoneDevice> reload(String deviceId) {
        return repo.findByDeviceId(deviceId);
    }

    private static <T> Mono<T> notFound(String deviceId) {
        return Mono.error(ApiException.notFound("phone '" + deviceId + "' not found"));
    }

    /** Guard the AUTHORITATIVE discriminator to the closed vocabulary (defence-in-depth over
     *  the DTO @Pattern and the DB CHECK — a bad value is a 422, never a silent write). */
    private static String normalizeMode(String mode) {
        String m = mode == null ? "" : mode.trim();
        if (PhoneDevice.MANAGEMENT_MESH_OWNED.equals(m) || PhoneDevice.MANAGEMENT_UNMANAGED.equals(m)) {
            return m;
        }
        throw ApiException.unprocessable(
                "management mode must be '" + PhoneDevice.MANAGEMENT_MESH_OWNED + "' or '"
                + PhoneDevice.MANAGEMENT_UNMANAGED + "'");
    }
}
