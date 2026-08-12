package net.hugmesh.adminbff.notification;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code notification_delivery} (Liquibase
 * changeset 062/063). Derived finders cover the per-(outbox,channel) reads; the two
 * undelivered-scan finders are {@code @Query} constants because they LEFT JOIN
 * {@code notification_outbox} against this table with a correlated-subselect cursor
 * watermark (not expressible as a derived method). The {@link NotificationDeliveryRepository}
 * facade composes these into its public API.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 * This is a PLAIN INSERT (no ON CONFLICT): a duplicate {@code (outbox_id, channel)} surfaces
 * the UNIQUE-violation — the idempotency signal the facade's {@code record} maps to 0.
 */
public interface NotificationDeliveryR2dbcRepository
        extends ReactiveCrudRepository<NotificationDelivery, String> {

    /**
     * Insert one delivery row with a DB-generated id (id OMITTED → filled from the column
     * DEFAULT; {@code RETURNING id} reads the generated varchar(36) back). The supplied
     * columns match the {@link NotificationDelivery} column order (id excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO notification_delivery \
            (outbox_id, channel, status, sent_at) \
            VALUES (:outbox_id, :channel, :status, :sent_at) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("outbox_id") String outboxId,
                                   @Param("channel") String channel,
                                   @Param("status") String status,
                                   @Param("sent_at") Instant sentAt);

    /** The recorded delivery row for an outbox row on a channel
     *  ({@code WHERE outbox_id=? AND channel=?}), or empty. */
    Mono<NotificationDelivery> findByOutboxIdAndChannel(String outboxId, String channel);

    /** Whether a delivery row exists for an outbox row on a channel
     *  ({@code SELECT count(*) > 0 WHERE outbox_id=? AND channel=?}). */
    Mono<Boolean> existsByOutboxIdAndChannel(String outboxId, String channel);

    /**
     * The oldest CHANNEL-undelivered outbox rows, oldest-first by {@code (created_at, id)}.
     * Cold-start variant (null cursor): no watermark lower bound. Behaviour-identical to
     * the facade's {@code LEFT JOIN ... d.id IS NULL} scan with no cursor.
     */
    String UNDELIVERED_COLD =
            "SELECT o.id AS id, o.domain AS domain, o.source_table AS source_table, "
            + "o.source_id AS source_id, o.category AS category, o.payload AS payload, "
            + "o.created_at AS created_at "
            + "FROM notification_outbox o "
            + "LEFT JOIN notification_delivery d ON d.outbox_id = o.id AND d.channel = :chan "
            + "WHERE d.id IS NULL "
            + "ORDER BY o.created_at, o.id";

    @Query(UNDELIVERED_COLD)
    Flux<NotificationOutbox> findUndeliveredCold(String chan);

    /**
     * The oldest CHANNEL-undelivered outbox rows AT OR ABOVE the cursor watermark
     * (resolving the watermark id's created_at via a scalar subselect; a missing watermark
     * row imposes no lower bound), oldest-first by {@code (created_at, id)}. Behaviour-
     * identical to the facade's cursor branch.
     */
    String UNDELIVERED_FROM_CURSOR =
            "SELECT o.id AS id, o.domain AS domain, o.source_table AS source_table, "
            + "o.source_id AS source_id, o.category AS category, o.payload AS payload, "
            + "o.created_at AS created_at "
            + "FROM notification_outbox o "
            + "LEFT JOIN notification_delivery d ON d.outbox_id = o.id AND d.channel = :chan "
            + "WHERE d.id IS NULL "
            + "AND ( o.created_at > (SELECT w.created_at FROM notification_outbox w WHERE w.id = :wmId) "
            + "  OR (o.created_at = (SELECT w.created_at FROM notification_outbox w WHERE w.id = :wmId) "
            + "      AND o.id >= :wmId) "
            + "  OR NOT EXISTS (SELECT 1 FROM notification_outbox w WHERE w.id = :wmId) ) "
            + "ORDER BY o.created_at, o.id";

    @Query(UNDELIVERED_FROM_CURSOR)
    Flux<NotificationOutbox> findUndeliveredFromCursor(String chan, String wmId);
}
