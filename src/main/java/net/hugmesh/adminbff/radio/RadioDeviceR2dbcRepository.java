package net.hugmesh.adminbff.radio;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code node_radio_device} (changeset 300). The
 * active-radio lookup, the scoped/unscoped admin lists, and the per-device active scan are
 * derived finders; the {@code MAX(generation)} aggregate and the two state-guarded CAS
 * UPDATEs (scoped + unscoped detach) plus the propagation-state partial UPDATE are
 * {@code @Query} static-final constants (an aggregate and CAS-on-state UPDATEs are not
 * derivable). The {@link RadioDeviceRepository} facade maps rows to/from the
 * {@link RadioDevice} domain record.
 *
 * <p>DB-GENERATED PK (changelog-200 idiom, inline in changeset 300): the varchar(36)
 * {@code id} carries a {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS
 * {@code id} and appends {@code RETURNING id} to read the database-generated string back
 * ({@code Mono<String>}).
 */
public interface RadioDeviceR2dbcRepository
        extends ReactiveCrudRepository<RadioDeviceRow, String> {

    /**
     * Insert a new radio with a DB-generated id (id OMITTED → filled from the column DEFAULT;
     * {@code RETURNING id} reads the generated varchar(36) back). The nullable {@code
     * detached_at}/{@code detached_by} are OMITTED (default NULL — the fresh-radio shape). The
     * supplied columns match the {@link RadioDeviceRow} column order (id + detach-audit
     * columns excluded); the per-transport NULL columns are bound as nulls.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO node_radio_device \
            (device_id, transport, serial_path, host, port, topic_root, channel_name, \
             gateway_node_id, radio_id, mesh_channel, state, domain, propagation_state, \
             generation, created_by, created_at) \
            VALUES (:device_id, :transport, :serial_path, :host, :port, :topic_root, \
             :channel_name, :gateway_node_id, :radio_id, :mesh_channel, :state, :domain, \
             :propagation_state, :generation, :created_by, :created_at) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("device_id") String deviceId,
                                   @Param("transport") String transport,
                                   @Param("serial_path") String serialPath,
                                   @Param("host") String host,
                                   @Param("port") Integer port,
                                   @Param("topic_root") String topicRoot,
                                   @Param("channel_name") String channelName,
                                   @Param("gateway_node_id") String gatewayNodeId,
                                   @Param("radio_id") String radioId,
                                   @Param("mesh_channel") int meshChannel,
                                   @Param("state") String state,
                                   @Param("domain") String domain,
                                   @Param("propagation_state") String propagationState,
                                   @Param("generation") long generation,
                                   @Param("created_by") String createdBy,
                                   @Param("created_at") Instant createdAt);

    /** The active radio for (deviceId, radioId), if any — the idempotency check. */
    Mono<RadioDeviceRow> findByDeviceIdAndRadioIdAndState(
            String deviceId, String radioId, String state);

    /** Radios for a brand, newest first — the scoped admin read. */
    Flux<RadioDeviceRow> findByDomainOrderByCreatedAtDesc(String domain);

    /** ALL radios (unscoped SUPERADMIN), domain then newest first. */
    Flux<RadioDeviceRow> findByOrderByDomainAscCreatedAtDesc();

    /** ALL active radios pinned to one device, by radio id — the per-node export scan. */
    Flux<RadioDeviceRow> findByDeviceIdAndStateOrderByRadioId(String deviceId, String state);

    /** The current MAX(generation) across ALL radio rows; 0 when empty. */
    String MAX_GENERATION = "SELECT COALESCE(MAX(generation), 0) FROM node_radio_device";

    @Query(MAX_GENERATION)
    Mono<Long> maxGeneration();

    /** CAS {@code active -> detached} for one id in a brand, stamping audit + bumping gen. */
    String DETACH_SCOPED =
            "UPDATE node_radio_device "
            + "SET state = 'detached', detached_at = now(), detached_by = :by, "
            + "    generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active' AND domain = :domain";

    @Modifying
    @Query(DETACH_SCOPED)
    Mono<Long> detachScoped(String id, String by, long gen, String domain);

    /** CAS {@code active -> detached} for one id (unscoped SUPERADMIN). */
    String DETACH_ALL =
            "UPDATE node_radio_device "
            + "SET state = 'detached', detached_at = now(), detached_by = :by, "
            + "    generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(DETACH_ALL)
    Mono<Long> detachAll(String id, String by, long gen);

    /** Record the on-node meshbridge reconcile propagation outcome for a radio. */
    String UPDATE_PROP =
            "UPDATE node_radio_device SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);
}
