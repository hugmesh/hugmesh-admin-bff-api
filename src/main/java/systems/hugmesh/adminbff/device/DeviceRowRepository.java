package systems.hugmesh.adminbff.device;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code device_registry} (changeset 011). Derived
 * finders cover the fingerprint lookup, the unscoped + per-mesh + per-domain ordered
 * lists, and the scoped delete; the {@link DeviceRegistryRepository} facade maps rows
 * to/from {@link Device} and composes the unscoped-delete count.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 */
public interface DeviceRowRepository extends ReactiveCrudRepository<DeviceRow, String> {

    /**
     * Register a new device with a DB-generated id (id OMITTED → filled from the column
     * DEFAULT; {@code RETURNING id} reads the generated varchar(36) back). The 11 supplied
     * columns match the {@link DeviceRow} column order (id excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO device_registry \
            (machine_key_fp, hostname, tailnet_id, image_type, hardware_class, owner_type, \
             physical_owner, domain, mesh_id, created_at, last_seen_at) \
            VALUES (:machine_key_fp, :hostname, :tailnet_id, :image_type, :hardware_class, \
             :owner_type, :physical_owner, :domain, :mesh_id, :created_at, :last_seen_at) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("machine_key_fp") String machineKeyFp,
                                   @Param("hostname") String hostname,
                                   @Param("tailnet_id") String tailnetId,
                                   @Param("image_type") String imageType,
                                   @Param("hardware_class") String hardwareClass,
                                   @Param("owner_type") String ownerType,
                                   @Param("physical_owner") String physicalOwner,
                                   @Param("domain") String domain,
                                   @Param("mesh_id") String meshId,
                                   @Param("created_at") Instant createdAt,
                                   @Param("last_seen_at") Instant lastSeenAt);

    /** The device with this stable machine-key fingerprint, if any (UNIQUE). */
    Mono<DeviceRow> findByMachineKeyFp(String machineKeyFp);

    /** All devices (every brand), domain-then-hostname ordered (the signed export). */
    Flux<DeviceRow> findAllByOrderByDomainAscHostnameAsc();

    /** All devices in one mesh, domain-then-hostname ordered (the per-mesh export scan). */
    Flux<DeviceRow> findByMeshIdOrderByDomainAscHostnameAsc(String meshId);

    /** Devices in one brand, hostname-ordered (the scoped admin read surface). */
    Flux<DeviceRow> findByDomainOrderByHostname(String domain);

    /** Scoped delete: by id AND domain (returns rows deleted). */
    Mono<Long> deleteByIdAndDomain(String id, String domain);
}
