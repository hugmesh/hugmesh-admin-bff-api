package net.hugmesh.adminbff.storage;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code node_storage_pool} (changeset 085). The
 * active-disk lookup, the scoped/unscoped admin lists, and the per-device active scan are
 * derived finders; the {@code MAX(generation)} aggregate and the two state-guarded CAS
 * UPDATEs (scoped + unscoped detach) plus the propagation-state partial UPDATE are
 * {@code @Query} static-final constants (an aggregate and CAS-on-state UPDATEs are not
 * derivable). The {@link StoragePoolRepository} facade maps rows to/from the
 * {@link StoragePool} domain record.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 */
public interface StoragePoolR2dbcRepository
        extends ReactiveCrudRepository<StoragePoolRow, String> {

    /**
     * Insert a new pool with a DB-generated id (id OMITTED → filled from the column DEFAULT;
     * {@code RETURNING id} reads the generated varchar(36) back). The nullable {@code
     * detached_at}/{@code detached_by} are OMITTED (default NULL — the fresh-pool shape). The
     * supplied columns match the {@link StoragePoolRow} column order (id + detach-audit
     * columns excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO node_storage_pool \
            (device_id, disk_serial, pool_path, reserved_bytes, is_exclusive, filesystem, \
             state, domain, propagation_state, generation, created_by, created_at) \
            VALUES (:device_id, :disk_serial, :pool_path, :reserved_bytes, :is_exclusive, \
             :filesystem, :state, :domain, :propagation_state, :generation, :created_by, \
             :created_at) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("device_id") String deviceId,
                                   @Param("disk_serial") String diskSerial,
                                   @Param("pool_path") String poolPath,
                                   @Param("reserved_bytes") long reservedBytes,
                                   @Param("is_exclusive") boolean isExclusive,
                                   @Param("filesystem") String filesystem,
                                   @Param("state") String state,
                                   @Param("domain") String domain,
                                   @Param("propagation_state") String propagationState,
                                   @Param("generation") long generation,
                                   @Param("created_by") String createdBy,
                                   @Param("created_at") Instant createdAt);

    /** The active pool for (deviceId, diskSerial), if any — the idempotency check. */
    Mono<StoragePoolRow> findByDeviceIdAndDiskSerialAndState(
            String deviceId, String diskSerial, String state);

    /** Pools for a brand, newest first — the scoped admin read. */
    Flux<StoragePoolRow> findByDomainOrderByCreatedAtDesc(String domain);

    /** ALL pools (unscoped SUPERADMIN), domain then newest first. */
    Flux<StoragePoolRow> findByOrderByDomainAscCreatedAtDesc();

    /** ALL active pools pinned to one device, by disk serial — the per-node export scan. */
    Flux<StoragePoolRow> findByDeviceIdAndStateOrderByDiskSerial(String deviceId, String state);

    /** The current MAX(generation) across ALL pool rows; 0 when empty. */
    String MAX_GENERATION = "SELECT COALESCE(MAX(generation), 0) FROM node_storage_pool";

    @Query(MAX_GENERATION)
    Mono<Long> maxGeneration();

    /** CAS {@code active -> detached} for one id in a brand, stamping audit + bumping gen. */
    String DETACH_SCOPED =
            "UPDATE node_storage_pool "
            + "SET state = 'detached', detached_at = now(), detached_by = :by, "
            + "    generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active' AND domain = :domain";

    @Modifying
    @Query(DETACH_SCOPED)
    Mono<Long> detachScoped(String id, String by, long gen, String domain);

    /** CAS {@code active -> detached} for one id (unscoped SUPERADMIN). */
    String DETACH_ALL =
            "UPDATE node_storage_pool "
            + "SET state = 'detached', detached_at = now(), detached_by = :by, "
            + "    generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(DETACH_ALL)
    Mono<Long> detachAll(String id, String by, long gen);

    /** Record the reconcile/patch propagation outcome for a pool. */
    String UPDATE_PROP =
            "UPDATE node_storage_pool SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);
}
