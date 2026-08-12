package net.hugmesh.adminbff.phone;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code phone_device} (Liquibase changesets
 * 302 + 303) — the MDM phone registry. The device-id lookup is a derived finder; the
 * first ingest is the hand-written {@code INSERT ... RETURNING id} (the PK is a DB-generated
 * {@code (gen_random_uuid())::text} varchar, changelog-200 idiom — Spring Data cannot
 * auto-generate string PKs); a re-ingest is the atomic {@link #refresh} UPDATE
 * ({@code ingest_count = ingest_count + 1} is not expressible as a full-entity save).
 * The {@link PhoneDeviceRepository} facade composes these into the portable
 * findByDeviceId-then-update|insert upsert, exactly mirroring
 * {@link net.hugmesh.adminbff.device.DeviceEnrollmentRowRepository}.
 */
public interface PhoneDeviceRowRepository extends ReactiveCrudRepository<PhoneDeviceRow, String> {

    /**
     * Insert a first-ingest row with a DB-generated id: {@code id} is OMITTED (filled from
     * the {@code (gen_random_uuid())::text} column DEFAULT); {@code RETURNING id} reads the
     * generated varchar(36) back. The two ingest timestamps are deliberately OMITTED too —
     * the columns' {@code now()} defaults stamp them with the SAME (Postgres) clock the
     * re-ingest {@link #refresh} uses, so the {@code last_ingested_at} fleet ordering never
     * mixes the BFF JVM clock with the DB clock. {@code ingest_count} likewise takes its
     * column default (1). The facade re-reads the row after insert, so callers only ever
     * see DB-stamped values.
     *
     * <p><b>TRUST BOUNDARY.</b> The seven changeset-304 columns
     * ({@code management_mode}, {@code lock_state}, {@code lock_propagation_state},
     * {@code lock_generation}, {@code lock_reason}, {@code lock_actor},
     * {@code lock_updated_at}) are OPERATOR-authoritative and are OMITTED here on PURPOSE —
     * they take their column DEFAULTs (a fresh BYOD ingest lands {@code unmanaged}/
     * {@code unlocked}/generation 0). The ingest channel is device-reported and spoofable,
     * so it must NEVER write management or lock state; that is the /bff/superadmin plane's
     * job via {@link #lockManaged}/{@link #unlock}/{@link #setManagementMode}.
     *
     * <p><b>Device-reported columns ARE written.</b> The two changeset-307 columns
     * ({@code mdm_provider}, {@code intune_device_id}) are DEVICE-reported telemetry (which MDM
     * backend the wizard enrolled with), so — UNLIKE the operator-authoritative 304/305 columns
     * above — they ARE in the INSERT list (like {@code mdm_dpc_package}/{@code mdm_set_via}). A
     * blank/absent provider is normalised to {@code 'headwind'} in the service, so the NOT-NULL
     * column always receives a value.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO phone_device \
            (device_id, device_class, serial, codename, marketing_name, os, os_version, \
             superdomain, login_server, tailscale_ip, tailscale_hostname, role, \
             attached_domain, enterprise_profile_present, enterprise_profile_user_id, \
             enterprise_profile_credential_custody, mdm_enrolled, mdm_dpc_package, \
             mdm_headwind_url, mdm_set_via, mdm_enrolled_at, attestation_url, \
             auditor_package, attestation_verdict, enrolled_at, generated_at, \
             mdm_provider, intune_device_id) \
            VALUES (:deviceId, :deviceClass, :serial, :codename, :marketingName, :os, \
             :osVersion, :superdomain, :loginServer, :tailscaleIp, :tailscaleHostname, \
             :role, :attachedDomain, :enterpriseProfilePresent, :enterpriseProfileUserId, \
             :enterpriseProfileCredentialCustody, :mdmEnrolled, :mdmDpcPackage, \
             :mdmHeadwindUrl, :mdmSetVia, :mdmEnrolledAt, :attestationUrl, \
             :auditorPackage, :attestationVerdict, :enrolledAt, :generatedAt, \
             :mdmProvider, :intuneDeviceId) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("deviceId") String deviceId,
                                   @Param("deviceClass") String deviceClass,
                                   @Param("serial") String serial,
                                   @Param("codename") String codename,
                                   @Param("marketingName") String marketingName,
                                   @Param("os") String os,
                                   @Param("osVersion") String osVersion,
                                   @Param("superdomain") String superdomain,
                                   @Param("loginServer") String loginServer,
                                   @Param("tailscaleIp") String tailscaleIp,
                                   @Param("tailscaleHostname") String tailscaleHostname,
                                   @Param("role") String role,
                                   @Param("attachedDomain") String attachedDomain,
                                   @Param("enterpriseProfilePresent") boolean enterpriseProfilePresent,
                                   @Param("enterpriseProfileUserId") Long enterpriseProfileUserId,
                                   @Param("enterpriseProfileCredentialCustody") String enterpriseProfileCredentialCustody,
                                   @Param("mdmEnrolled") boolean mdmEnrolled,
                                   @Param("mdmDpcPackage") String mdmDpcPackage,
                                   @Param("mdmHeadwindUrl") String mdmHeadwindUrl,
                                   @Param("mdmSetVia") String mdmSetVia,
                                   @Param("mdmEnrolledAt") Instant mdmEnrolledAt,
                                   @Param("attestationUrl") String attestationUrl,
                                   @Param("auditorPackage") String auditorPackage,
                                   @Param("attestationVerdict") String attestationVerdict,
                                   @Param("enrolledAt") Instant enrolledAt,
                                   @Param("generatedAt") Instant generatedAt,
                                   @Param("mdmProvider") String mdmProvider,
                                   @Param("intuneDeviceId") String intuneDeviceId);

    /** The registry row for this onboarding-stable device id, if any (UNIQUE). */
    Mono<PhoneDeviceRow> findByDeviceId(String deviceId);

    /** The whole fleet, newest activity first (the superadmin console read). */
    Flux<PhoneDeviceRow> findAllByOrderByLastIngestedAtDesc();

    /**
     * The caller's OWN fleet within their domain — the FLEET_ADMIN owner-scoped list
     * (changeset 305). BOTH predicates (physical_owner AND owner_domain) are the tenancy
     * wall: a device owned by a different subject, OR a device with a matching owner but a
     * different owner_domain, is simply not returned. A null owner column never matches (a
     * derived {@code =} finder binds the parameter, so an unassigned device is fleet-invisible
     * = fail-closed). Newest ingest activity first, mirroring the superadmin list.
     */
    Flux<PhoneDeviceRow> findByPhysicalOwnerAndOwnerDomainOrderByLastIngestedAtDesc(
            String physicalOwner, String ownerDomain);

    /**
     * One of the caller's OWN devices by id, scoped to owner AND domain (changeset 305). An
     * empty Mono when the device is unknown OR owned by another subject OR in another domain —
     * the FLEET_ADMIN {@code GET /{id}} maps empty to a 404 (no enumeration: a cross-owner
     * device is indistinguishable from an unknown one).
     */
    Mono<PhoneDeviceRow> findByDeviceIdAndPhysicalOwnerAndOwnerDomain(
            String deviceId, String physicalOwner, String ownerDomain);

    /**
     * Atomic re-ingest bump: refresh EVERY telemetry column from the new record,
     * {@code last_ingested_at = now()}, {@code ingest_count + 1}. {@code first_ingested_at}
     * and the identity ({@code device_id}, {@code id}) are deliberately untouched.
     *
     * <p><b>TRUST BOUNDARY.</b> The seven changeset-304 management/lock columns are NOT in
     * the SET list — a re-ingest of a MANAGED or LOCKED device leaves its operator state
     * exactly as the /bff/superadmin plane set it (proven by the repository test). Adding any
     * of them here would let the spoofable ingest channel clear a lock, which is the exact
     * attack this boundary exists to stop.
     *
     * <p>The changeset-307 {@code mdm_provider} / {@code intune_device_id} columns ARE in the
     * SET list — they are DEVICE-reported telemetry (which MDM backend enrolled the device), so
     * a re-ingest legitimately refreshes them, exactly like {@code mdm_dpc_package}. They are
     * advisory: the enforcer fans a lock to the matching DPC leg while the authoritative lock
     * state (never in this SET) is untouched.
     */
    String REFRESH = """
            UPDATE phone_device SET \
            device_class = :deviceClass, serial = :serial, codename = :codename, \
            marketing_name = :marketingName, os = :os, os_version = :osVersion, \
            superdomain = :superdomain, login_server = :loginServer, \
            tailscale_ip = :tailscaleIp, tailscale_hostname = :tailscaleHostname, \
            role = :role, attached_domain = :attachedDomain, \
            enterprise_profile_present = :enterpriseProfilePresent, \
            enterprise_profile_user_id = :enterpriseProfileUserId, \
            enterprise_profile_credential_custody = :enterpriseProfileCredentialCustody, \
            mdm_enrolled = :mdmEnrolled, mdm_dpc_package = :mdmDpcPackage, \
            mdm_headwind_url = :mdmHeadwindUrl, mdm_set_via = :mdmSetVia, \
            mdm_enrolled_at = :mdmEnrolledAt, \
            attestation_url = :attestationUrl, auditor_package = :auditorPackage, \
            attestation_verdict = :attestationVerdict, enrolled_at = :enrolledAt, \
            generated_at = :generatedAt, \
            mdm_provider = :mdmProvider, intune_device_id = :intuneDeviceId, \
            last_ingested_at = now(), \
            ingest_count = ingest_count + 1 \
            WHERE device_id = :deviceId""";

    @Modifying
    @Query(REFRESH)
    Mono<Long> refresh(@Param("deviceId") String deviceId,
                       @Param("deviceClass") String deviceClass,
                       @Param("serial") String serial,
                       @Param("codename") String codename,
                       @Param("marketingName") String marketingName,
                       @Param("os") String os,
                       @Param("osVersion") String osVersion,
                       @Param("superdomain") String superdomain,
                       @Param("loginServer") String loginServer,
                       @Param("tailscaleIp") String tailscaleIp,
                       @Param("tailscaleHostname") String tailscaleHostname,
                       @Param("role") String role,
                       @Param("attachedDomain") String attachedDomain,
                       @Param("enterpriseProfilePresent") boolean enterpriseProfilePresent,
                       @Param("enterpriseProfileUserId") Long enterpriseProfileUserId,
                       @Param("enterpriseProfileCredentialCustody") String enterpriseProfileCredentialCustody,
                       @Param("mdmEnrolled") boolean mdmEnrolled,
                       @Param("mdmDpcPackage") String mdmDpcPackage,
                       @Param("mdmHeadwindUrl") String mdmHeadwindUrl,
                       @Param("mdmSetVia") String mdmSetVia,
                       @Param("mdmEnrolledAt") Instant mdmEnrolledAt,
                       @Param("attestationUrl") String attestationUrl,
                       @Param("auditorPackage") String auditorPackage,
                       @Param("attestationVerdict") String attestationVerdict,
                       @Param("enrolledAt") Instant enrolledAt,
                       @Param("generatedAt") Instant generatedAt,
                       @Param("mdmProvider") String mdmProvider,
                       @Param("intuneDeviceId") String intuneDeviceId);

    // ── management + lockout CAS state machine (changeset 304) ───────────────────
    // Hand-written atomic transitions mirroring device_ssh_license's CAS + generation bump.
    // Each is a single UPDATE ... RETURNING lock_generation: the RETURNING both bumps the
    // MONOTONIC per-device generation in the same round-trip AND signals a match (an empty
    // Mono = no row matched, i.e. unknown device_id or a failed CAS guard). No @Modifying —
    // exactly like insertReturningId, RETURNING projects a value the caller reads back.

    /**
     * Set the AUTHORITATIVE management_mode (SUPERADMIN plane). Plain CAS-by-key: an empty
     * Mono means the device_id is unknown (mapped to 404 upstream). Does NOT touch lock
     * state — clearing a LOCKED managed device to unmanaged goes through
     * {@link #clearManagedAndUnlock} first so no locked orphan is left behind.
     */
    String SET_MANAGEMENT_MODE = """
            UPDATE phone_device SET management_mode = :mode \
            WHERE device_id = :deviceId \
            RETURNING lock_generation""";

    @Query(SET_MANAGEMENT_MODE)
    Mono<Long> setManagementMode(@Param("deviceId") String deviceId, @Param("mode") String mode);

    /**
     * Clear management_mode to 'unmanaged' AND unlock in one atomic step, guarded on
     * {@code lock_state = 'locked'} so it fires ONLY when there is a lock to clear (no
     * locked orphan). Bumps the monotonic generation and marks propagation pending so the
     * enforcement UNLOCK is pushed. An empty Mono means the device was not locked (the
     * caller then does a plain {@link #setManagementMode}).
     */
    String CLEAR_MANAGED_AND_UNLOCK = """
            UPDATE phone_device SET \
            management_mode = 'unmanaged', lock_state = 'unlocked', \
            lock_generation = lock_generation + 1, lock_propagation_state = 'pending', \
            lock_reason = NULL, lock_actor = :actor, lock_updated_at = now() \
            WHERE device_id = :deviceId AND lock_state = 'locked' \
            RETURNING lock_generation""";

    @Query(CLEAR_MANAGED_AND_UNLOCK)
    Mono<Long> clearManagedAndUnlock(@Param("deviceId") String deviceId,
                                     @Param("actor") String actor);

    /**
     * Lock a MANAGED device: CAS guarded on {@code management_mode = 'mesh_owned'} (a BYOD
     * lock never matches — an empty Mono, surfaced as a 409). Sets lock_state=locked, bumps
     * the monotonic generation, marks propagation pending, and stamps reason/actor/updated_at.
     * Re-locking an already-locked managed device re-runs (bumps generation again) — the
     * enforcement replay is intentional.
     */
    String LOCK_MANAGED = """
            UPDATE phone_device SET \
            lock_state = 'locked', lock_generation = lock_generation + 1, \
            lock_propagation_state = 'pending', lock_reason = :reason, \
            lock_actor = :actor, lock_updated_at = now() \
            WHERE device_id = :deviceId AND management_mode = 'mesh_owned' \
            RETURNING lock_generation""";

    @Query(LOCK_MANAGED)
    Mono<Long> lockManaged(@Param("deviceId") String deviceId, @Param("reason") String reason,
                           @Param("actor") String actor);

    /**
     * Unlock a device: lock_state=unlocked, bump the monotonic generation, mark propagation
     * pending, clear the reason, stamp actor/updated_at. Not guarded on the prior lock_state
     * (an unlock is always recorded so the generation stays monotonic and the enforcement
     * unlock is re-asserted). An empty Mono means the device_id is unknown (404).
     */
    String UNLOCK = """
            UPDATE phone_device SET \
            lock_state = 'unlocked', lock_generation = lock_generation + 1, \
            lock_propagation_state = 'pending', lock_reason = NULL, \
            lock_actor = :actor, lock_updated_at = now() \
            WHERE device_id = :deviceId \
            RETURNING lock_generation""";

    @Query(UNLOCK)
    Mono<Long> unlock(@Param("deviceId") String deviceId, @Param("actor") String actor);

    // ── owner assignment + OWNER-SCOPED lock/unlock (changeset 305, fleet-admin wall) ─────
    // The owner columns are set ONLY here (SUPERADMIN plane). The scoped lock/unlock add the
    // owner+domain predicate to the CAS WHERE clause so a FLEET_ADMIN's mutation against a
    // device it does not own (or in another domain) matches 0 rows — an empty Mono the service
    // maps to a 404, never a cross-owner lock. RETURNING lock_generation both signals a match
    // and hands back the bumped generation, exactly like the unscoped queries above.

    /**
     * Set the AUTHORITATIVE fleet owner (physical_owner + owner_domain) — SUPERADMIN plane
     * only ({@code PUT /bff/superadmin/phone-devices/{id}/owner}). Plain CAS-by-key: an empty
     * Mono means the device_id is unknown (404 upstream). Does NOT touch management/lock state.
     */
    String SET_OWNER = """
            UPDATE phone_device SET physical_owner = :owner, owner_domain = :domain \
            WHERE device_id = :deviceId \
            RETURNING lock_generation""";

    @Query(SET_OWNER)
    Mono<Long> setOwner(@Param("deviceId") String deviceId, @Param("owner") String owner,
                        @Param("domain") String domain);

    /**
     * OWNER-SCOPED lock of a MANAGED device — the fleet-admin lock. Adds the owner+domain
     * predicate to {@link #LOCK_MANAGED}'s CAS: guarded on {@code management_mode='mesh_owned'
     * AND physical_owner=:owner AND owner_domain=:domain}, so a cross-owner / cross-domain /
     * BYOD lock matches NO row (empty Mono). Same lock_state/generation/propagation/reason/
     * actor writes as the unscoped lock.
     */
    String LOCK_MANAGED_SCOPED = """
            UPDATE phone_device SET \
            lock_state = 'locked', lock_generation = lock_generation + 1, \
            lock_propagation_state = 'pending', lock_reason = :reason, \
            lock_actor = :actor, lock_updated_at = now() \
            WHERE device_id = :deviceId AND management_mode = 'mesh_owned' \
            AND physical_owner = :owner AND owner_domain = :domain \
            RETURNING lock_generation""";

    @Query(LOCK_MANAGED_SCOPED)
    Mono<Long> lockManagedScoped(@Param("deviceId") String deviceId, @Param("reason") String reason,
                                 @Param("actor") String actor, @Param("owner") String owner,
                                 @Param("domain") String domain);

    /**
     * OWNER-SCOPED unlock — the fleet-admin unlock. Adds the owner+domain predicate to
     * {@link #UNLOCK}'s CAS ({@code physical_owner=:owner AND owner_domain=:domain}); an
     * unlock of a device the caller does not own (or in another domain) matches NO row (empty
     * Mono, mapped to 404). Not guarded on prior lock_state — an unlock is always re-asserted
     * so the generation stays monotonic.
     */
    String UNLOCK_SCOPED = """
            UPDATE phone_device SET \
            lock_state = 'unlocked', lock_generation = lock_generation + 1, \
            lock_propagation_state = 'pending', lock_reason = NULL, \
            lock_actor = :actor, lock_updated_at = now() \
            WHERE device_id = :deviceId \
            AND physical_owner = :owner AND owner_domain = :domain \
            RETURNING lock_generation""";

    @Query(UNLOCK_SCOPED)
    Mono<Long> unlockScoped(@Param("deviceId") String deviceId, @Param("actor") String actor,
                            @Param("owner") String owner, @Param("domain") String domain);

    /**
     * Record the push-with-ack enforcement outcome for a specific generation. GUARDED on
     * {@code lock_generation = :generation} so a stale enforcement result NEVER clobbers the
     * propagation state of a newer lock/unlock (the max-generation rollback guard, mirroring
     * device_ssh_license). Returns rows-updated (0 = a newer generation already superseded).
     */
    String UPDATE_LOCK_PROPAGATION = """
            UPDATE phone_device SET lock_propagation_state = :ps \
            WHERE device_id = :deviceId AND lock_generation = :generation""";

    @Modifying
    @Query(UPDATE_LOCK_PROPAGATION)
    Mono<Long> updateLockPropagation(@Param("deviceId") String deviceId,
                                     @Param("generation") long generation,
                                     @Param("ps") String ps);
}
