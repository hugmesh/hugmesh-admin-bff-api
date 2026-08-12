package net.hugmesh.adminbff.radio;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code node_radio_device} (schema in Liquibase
 * {@code db/changelog/300-node-radio-device.xml}). DB-generated {@code varchar(36)} UUID
 * ids (changelog-200 idiom), the verified {@code scope == null || scope.scoped() ? WHERE
 * domain=:domain : unscoped} branch for the ADMIN read surface,
 * {@code findActive}-before-insert idempotency (the partial unique index is the Postgres
 * backstop), and UNSCOPED reads for the signed per-node export.
 *
 * <p>Backed by the Spring Data {@link RadioDeviceR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link RadioDeviceRow} entity to/from the
 * {@link RadioDevice} domain record. CLONES the
 * {@link net.hugmesh.adminbff.storage.StoragePoolRepository} facade verbatim.
 */
@Repository
public class RadioDeviceRepository {

    private final RadioDeviceR2dbcRepository repo;

    public RadioDeviceRepository(RadioDeviceR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── attach (findActive-then-insert idempotency) ─────────────────────────────

    /** The active radio for (deviceId, radioId), if any — the idempotency check.
     *  UNSCOPED (the caller has already passed the ownership gate). */
    public Mono<RadioDevice> findActiveRadio(String deviceId, String radioId) {
        return repo.findByDeviceIdAndRadioIdAndState(deviceId, radioId, RadioDevice.STATE_ACTIVE)
                .map(RadioDeviceRow::toDomain);
    }

    /**
     * Insert a new ACTIVE radio (DB-generated id) at the given generation, returning it.
     * The caller (the service) has resolved the node FIRST, passed the ownership ALLOW/DENY
     * gate, validated the per-transport shape, and stamped {@code domain} from the device's
     * residency [FIX-NODEFAULT] before this insert.
     */
    public Mono<RadioDevice> insertActive(RadioDevice r, long generation) {
        Instant createdAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changeset
        // 300); RETURNING id hands back the generated string, which we map into the persisted
        // RadioDevice with the SAME field order/values as before (detach-audit columns NULL).
        return repo.insertReturningId(r.deviceId(), r.transport(), r.serialPath(), r.host(),
                        r.port(), r.topicRoot(), r.channelName(), r.gatewayNodeId(), r.radioId(),
                        r.meshChannel(), RadioDevice.STATE_ACTIVE, r.domain(),
                        RadioDevice.PROP_PENDING, generation, r.createdBy(), createdAt)
                .map(genId -> new RadioDevice(genId, r.deviceId(), r.transport(), r.serialPath(),
                        r.host(), r.port(), r.topicRoot(), r.channelName(), r.gatewayNodeId(),
                        r.radioId(), r.meshChannel(), RadioDevice.STATE_ACTIVE, r.domain(),
                        RadioDevice.PROP_PENDING, generation, r.createdBy(), createdAt,
                        null, null));
    }

    // ── read (admin surface, scoped) ────────────────────────────────────────────

    /** Radios VISIBLE to the given tenant scope — the ADMIN read surface. A scoped admin
     *  sees ONLY their brand's radios; SUPERADMIN (unscoped) sees all. Fail-closed: a null
     *  scope is treated as scoped to NO_DOMAIN. */
    public Flux<RadioDevice> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByCreatedAtDesc(domain).map(RadioDeviceRow::toDomain);
        }
        return repo.findByOrderByDomainAscCreatedAtDesc().map(RadioDeviceRow::toDomain);
    }

    /** A single radio by id. UNSCOPED — the detach flow resolves a radio's node;
     *  the controller gates the surface. */
    public Mono<RadioDevice> findById(String id) {
        return repo.findById(id).map(RadioDeviceRow::toDomain);
    }

    // ── read (export, UNSCOPED) ─────────────────────────────────────────────────

    /** ALL active radios pinned to one device. UNSCOPED — the per-node signed export scan. */
    public Flux<RadioDevice> listActiveForDevice(String deviceId) {
        return repo.findByDeviceIdAndStateOrderByRadioId(deviceId, RadioDevice.STATE_ACTIVE)
                .map(RadioDeviceRow::toDomain);
    }

    /** The current maximum {@code generation} across ALL radio rows — the monotonic counter
     *  the export stamps and a node's rollback guard compares against. Returns 0 when the
     *  table is empty. */
    public Mono<Long> maxGeneration() {
        return repo.maxGeneration().defaultIfEmpty(0L);
    }

    // ── detach (CAS, audited, generation bump) ──────────────────────────────────

    /**
     * Compare-and-swap {@code active -> detached} for one radio id at a NEW generation,
     * guarded on the current state so only ONE writer wins (returns the rows-updated count:
     * 1 = detached + audit stamped, 0 = already detached / absent / out of scope). The row
     * is NEVER deleted while history matters. A scoped principal can only detach a radio in
     * their own brand; SUPERADMIN any (the controller + service gate ownership upstream).
     */
    public Mono<Long> detach(String id, String detachedBy, long newGeneration, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.detachScoped(id, detachedBy, newGeneration, domain);
        }
        return repo.detachAll(id, detachedBy, newGeneration);
    }

    /** Record the on-node meshbridge reconcile propagation outcome
     *  (pending/applied/failed/degraded) for a radio. UNSCOPED — driven by the reconcile/ack
     *  path (the future on-node meshbridge agent's write surface). */
    public Mono<Long> updatePropagationState(String id, String propagationState) {
        return repo.updatePropagationState(id, propagationState);
    }
}
