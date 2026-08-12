package net.hugmesh.adminbff.phone;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code phone_device} — the MDM phone registry the wizard's
 * {@code phone-ingest/v1}|{@code v2} records land in (schema in Liquibase
 * {@code db/changelog/302-phone-device.xml} + {@code 303-phone-device-mdm.xml}).
 *
 * <p>Backed by the Spring Data {@link PhoneDeviceRowRepository} (no raw
 * {@code DatabaseClient}); maps the {@link PhoneDeviceRow} entity to the
 * {@link PhoneDevice} domain record. The upsert is the portable
 * findByDeviceId-then-update|insert idiom; the re-ingest bump is the atomic refresh
 * UPDATE. Mirrors {@link net.hugmesh.adminbff.device.DeviceEnrollmentRepository}.
 *
 * <p>NO authorizing columns are read or written here — this is fleet inventory/telemetry a
 * SUPERADMIN reads, never an access grant.
 */
@Repository
public class PhoneDeviceRepository {

    private final PhoneDeviceRowRepository repo;

    public PhoneDeviceRepository(PhoneDeviceRowRepository repo) {
        this.repo = repo;
    }

    /** The registry record for this onboarding-stable device id, if any (UNIQUE). */
    public Mono<PhoneDevice> findByDeviceId(String deviceId) {
        return repo.findByDeviceId(deviceId).map(PhoneDeviceRow::toDomain);
    }

    /** The whole phone fleet, newest ingest activity first. */
    public Flux<PhoneDevice> listAll() {
        return repo.findAllByOrderByLastIngestedAtDesc().map(PhoneDeviceRow::toDomain);
    }

    /** The caller's OWN fleet within their domain (changeset 305) — the FLEET_ADMIN list.
     *  BOTH predicates (owner AND domain) are the tenancy wall. */
    public Flux<PhoneDevice> listOwned(String owner, String domain) {
        return repo.findByPhysicalOwnerAndOwnerDomainOrderByLastIngestedAtDesc(owner, domain)
                .map(PhoneDeviceRow::toDomain);
    }

    /** One of the caller's OWN devices by id, scoped to owner AND domain; empty when unknown
     *  OR owned by another subject OR in another domain (the fleet-admin 404, no enumeration). */
    public Mono<PhoneDevice> findByDeviceIdOwned(String deviceId, String owner, String domain) {
        return repo.findByDeviceIdAndPhysicalOwnerAndOwnerDomain(deviceId, owner, domain)
                .map(PhoneDeviceRow::toDomain);
    }

    /**
     * UPSERT an ingest record. A first ingest INSERTs (ingest_count=1); a re-ingest
     * refreshes every telemetry column, bumps last_ingested_at + ingest_count, and
     * preserves first_ingested_at + the row identity. Returns the resulting row, always
     * RE-READ from the store — callers only ever see DB-stamped values (one clock source
     * for the last_ingested_at fleet ordering; no in-memory echo).
     *
     * <p>The find-then-insert idiom races with itself: two concurrent FIRST ingests of one
     * device_id both observe empty and both take the insert branch — the loser hits
     * {@code uq_phone_device_device_id} (the UNIQUE keeps the data right). That loser is
     * folded back into the refresh branch instead of surfacing a 500 (the operator's curl
     * has no retry), which is also where a benign wizard re-run lands.
     */
    public Mono<PhoneDevice> upsert(PhoneIngest r) {
        return repo.findByDeviceId(r.deviceId())
                .flatMap(existing -> refresh(r))
                .switchIfEmpty(Mono.defer(() -> insert(r)
                        .onErrorResume(DuplicateKeyException.class, lostRace -> refresh(r))));
    }

    private Mono<PhoneDevice> refresh(PhoneIngest r) {
        return repo.refresh(r.deviceId(), r.deviceClass(), r.serial(), r.codename(),
                        r.marketingName(), r.os(), r.osVersion(), r.superdomain(),
                        r.loginServer(), r.tailscaleIp(), r.tailscaleHostname(), r.role(),
                        r.attachedDomain(), r.enterpriseProfilePresent(),
                        r.enterpriseProfileUserId(), r.enterpriseProfileCredentialCustody(),
                        r.mdmEnrolled(), r.mdmDpcPackage(), r.mdmHeadwindUrl(),
                        r.mdmSetVia(), r.mdmEnrolledAt(),
                        r.attestationUrl(), r.auditorPackage(), r.attestationVerdict(),
                        r.enrolledAt(), r.generatedAt(), r.mdmProvider(), r.intuneDeviceId())
                .then(findByDeviceId(r.deviceId()));
    }

    private Mono<PhoneDevice> insert(PhoneIngest r) {
        // INSERT omits id AND the ingest timestamps/count (all filled from column
        // DEFAULTs — the id from (gen_random_uuid())::text, the timestamps from the
        // DB-clock now(), the count from 1); the row is then re-read so the caller gets
        // exactly what the store holds. The changeset-304 management/lock columns are
        // likewise omitted (they take their DEFAULTs — a fresh BYOD ingest is
        // unmanaged/unlocked/generation 0) — the ingest channel NEVER writes operator state.
        return repo.insertReturningId(r.deviceId(), r.deviceClass(), r.serial(), r.codename(),
                        r.marketingName(), r.os(), r.osVersion(), r.superdomain(),
                        r.loginServer(), r.tailscaleIp(), r.tailscaleHostname(), r.role(),
                        r.attachedDomain(), r.enterpriseProfilePresent(),
                        r.enterpriseProfileUserId(), r.enterpriseProfileCredentialCustody(),
                        r.mdmEnrolled(), r.mdmDpcPackage(), r.mdmHeadwindUrl(),
                        r.mdmSetVia(), r.mdmEnrolledAt(),
                        r.attestationUrl(), r.auditorPackage(), r.attestationVerdict(),
                        r.enrolledAt(), r.generatedAt(), r.mdmProvider(), r.intuneDeviceId())
                .flatMap(genId -> findByDeviceId(r.deviceId()));
    }

    // ── management + lockout CAS transitions (changeset 304, SUPERADMIN plane) ────
    // Thin pass-throughs to the atomic RETURNING-generation queries. Each Mono emits the new
    // monotonic lock_generation on a match and is EMPTY on no-match (unknown device or a
    // failed CAS guard) — the service maps empty to the right 404/409.

    /** Set the authoritative management_mode; empty when the device_id is unknown. */
    public Mono<Long> setManagementMode(String deviceId, String mode) {
        return repo.setManagementMode(deviceId, mode);
    }

    /** Clear a LOCKED managed device to unmanaged AND unlock it atomically; empty when it
     *  was not locked (the caller falls back to a plain {@link #setManagementMode}). */
    public Mono<Long> clearManagedAndUnlock(String deviceId, String actor) {
        return repo.clearManagedAndUnlock(deviceId, actor);
    }

    /** Lock a device, CAS-guarded on management_mode='mesh_owned'; empty when the device is
     *  absent OR not managed (a BYOD lock never matches). Emits the new generation. */
    public Mono<Long> lockManaged(String deviceId, String reason, String actor) {
        return repo.lockManaged(deviceId, reason, actor);
    }

    /** Unlock a device; empty when the device_id is unknown. Emits the new generation. */
    public Mono<Long> unlock(String deviceId, String actor) {
        return repo.unlock(deviceId, actor);
    }

    // ── owner assignment + OWNER-SCOPED lock/unlock (changeset 305) ──────────────

    /** Set the authoritative fleet owner (physical_owner + owner_domain); empty when the
     *  device_id is unknown (SUPERADMIN plane). */
    public Mono<Long> setOwner(String deviceId, String owner, String domain) {
        return repo.setOwner(deviceId, owner, domain);
    }

    /** OWNER-SCOPED lock (CAS on mesh_owned AND owner AND domain); empty when the device is
     *  absent OR not owned-by-caller-in-domain OR BYOD (a cross-owner lock never matches). */
    public Mono<Long> lockManagedOwned(String deviceId, String reason, String actor,
                                       String owner, String domain) {
        return repo.lockManagedScoped(deviceId, reason, actor, owner, domain);
    }

    /** OWNER-SCOPED unlock (CAS on owner AND domain); empty when the device is absent OR not
     *  owned-by-caller-in-domain. Emits the new generation. */
    public Mono<Long> unlockOwned(String deviceId, String actor, String owner, String domain) {
        return repo.unlockScoped(deviceId, actor, owner, domain);
    }

    /** Record the enforcement outcome for a generation (guarded so a stale result never
     *  clobbers a newer lock/unlock). Returns rows-updated (0 = superseded). */
    public Mono<Long> updateLockPropagation(String deviceId, long generation, String propagationState) {
        return repo.updateLockPropagation(deviceId, generation, propagationState);
    }
}
