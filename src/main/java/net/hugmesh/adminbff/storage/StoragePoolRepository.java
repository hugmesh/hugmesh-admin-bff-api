package net.hugmesh.adminbff.storage;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code node_storage_pool} (schema in Liquibase
 * {@code db/changelog/085-node-storage.xml}). App-generated {@code varchar(36)} UUID ids
 * (portable across Postgres + the H2 test store), the verified {@code scope == null ||
 * scope.scoped() ? WHERE domain=:domain : unscoped} branch for the ADMIN read surface,
 * {@code findActive}-before-insert idempotency (the partial unique index is the Postgres
 * backstop; the H2 test store relies on the service guard), and UNSCOPED reads for the signed
 * per-node export.
 *
 * <p>Backed by the Spring Data {@link StoragePoolR2dbcRepository} (no raw {@code DatabaseClient});
 * maps the {@link StoragePoolRow} entity to/from the {@link StoragePool} domain record.
 */
@Repository
public class StoragePoolRepository {

    private final StoragePoolR2dbcRepository repo;

    public StoragePoolRepository(StoragePoolR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── attach (findActive-then-insert idempotency) ─────────────────────────────

    /** The active pool for (deviceId, diskSerial), if any — the idempotency check.
     *  UNSCOPED (the caller has already passed the ownership gate). */
    public Mono<StoragePool> findActiveDisk(String deviceId, String diskSerial) {
        return repo.findByDeviceIdAndDiskSerialAndState(deviceId, diskSerial, StoragePool.STATE_ACTIVE)
                .map(StoragePoolRow::toDomain);
    }

    /**
     * Insert a new ACTIVE pool (app-generated id) at the given generation, returning it.
     * The caller (the service) has resolved the node FIRST, passed the ownership ALLOW/DENY
     * gate, and stamped {@code domain} from the device's residency [FIX-NODEFAULT] before
     * this insert.
     */
    public Mono<StoragePool> insertActive(StoragePool p, long generation) {
        Instant createdAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id hands back the generated string, which we map into the persisted
        // StoragePool with the SAME field order/values as before (detach-audit columns NULL).
        return repo.insertReturningId(p.deviceId(), p.diskSerial(), p.poolPath(),
                        p.reservedBytes(), p.isExclusive(), p.filesystem(), StoragePool.STATE_ACTIVE,
                        p.domain(), StoragePool.PROP_PENDING, generation, p.createdBy(), createdAt)
                .map(genId -> new StoragePool(genId, p.deviceId(), p.diskSerial(), p.poolPath(),
                        p.reservedBytes(), p.isExclusive(), p.filesystem(), StoragePool.STATE_ACTIVE,
                        p.domain(), StoragePool.PROP_PENDING, generation, p.createdBy(),
                        createdAt, null, null));
    }

    // ── read (admin surface, scoped) ────────────────────────────────────────────

    /** Pools VISIBLE to the given tenant scope — the ADMIN read surface. A scoped admin
     *  sees ONLY their brand's pools; SUPERADMIN (unscoped) sees all. Fail-closed: a null
     *  scope is treated as scoped to NO_DOMAIN. */
    public Flux<StoragePool> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByCreatedAtDesc(domain).map(StoragePoolRow::toDomain);
        }
        return repo.findByOrderByDomainAscCreatedAtDesc().map(StoragePoolRow::toDomain);
    }

    /** A single pool by id. UNSCOPED — the assign flow resolves a pool's residency +
     *  capacity; the controller gates the surface. */
    public Mono<StoragePool> findById(String id) {
        return repo.findById(id).map(StoragePoolRow::toDomain);
    }

    // ── read (export, UNSCOPED) ─────────────────────────────────────────────────

    /** ALL active pools pinned to one device. UNSCOPED — the per-node signed export scan. */
    public Flux<StoragePool> listActiveForDevice(String deviceId) {
        return repo.findByDeviceIdAndStateOrderByDiskSerial(deviceId, StoragePool.STATE_ACTIVE)
                .map(StoragePoolRow::toDomain);
    }

    /** The current maximum {@code generation} across ALL pool rows — the monotonic counter
     *  the export stamps and a node's rollback guard compares against. Returns 0 when the
     *  table is empty. */
    public Mono<Long> maxGeneration() {
        return repo.maxGeneration().defaultIfEmpty(0L);
    }

    // ── detach (CAS, audited, generation bump) ──────────────────────────────────

    /**
     * Compare-and-swap {@code active -> detached} for one pool id at a NEW generation,
     * guarded on the current state so only ONE writer wins (returns the rows-updated count:
     * 1 = detached + audit stamped, 0 = already detached / absent / out of scope). The row
     * is NEVER deleted while history matters. A scoped principal can only detach a pool in
     * their own brand; SUPERADMIN any (the controller + service gate ownership upstream).
     */
    public Mono<Long> detach(String id, String detachedBy, long newGeneration, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.detachScoped(id, detachedBy, newGeneration, domain);
        }
        return repo.detachAll(id, detachedBy, newGeneration);
    }

    /** Record the reconcile/patch propagation outcome (pending/applied/failed/degraded) for
     *  a pool. UNSCOPED — driven by the reconcile/ack path (PR6). */
    public Mono<Long> updatePropagationState(String id, String propagationState) {
        return repo.updatePropagationState(id, propagationState);
    }
}
