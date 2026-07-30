package systems.hugmesh.adminbff.notification;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code notification_outbox} (Liquibase
 * changeset 062). Derived finders reproduce the facade's read semantics exactly; the
 * {@link NotificationOutboxRepository} facade composes these into its public API
 * (insert / insertIfAbsent / findBySource / byDomain / count) so callers and the
 * transactional-outbox compose-into-tx contract are unchanged.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 * This is a PLAIN INSERT (no ON CONFLICT): a duplicate {@code (source_table, source_id,
 * category)} surfaces the UNIQUE-violation — the dedup signal the facade's {@code
 * insertIfAbsent} maps to 0 (and the transactional {@code insert} surfaces as an error).
 */
public interface NotificationOutboxR2dbcRepository
        extends ReactiveCrudRepository<NotificationOutbox, String> {

    /**
     * Insert one outbox row with a DB-generated id (id OMITTED → filled from the column
     * DEFAULT; {@code RETURNING id} reads the generated varchar(36) back). Subscribed inside
     * the effect's reactive transaction by the facade so the INSERT is atomic with the effect
     * write. The supplied columns match the {@link NotificationOutbox} column order (id
     * excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO notification_outbox \
            (domain, source_table, source_id, category, payload, created_at) \
            VALUES (:domain, :source_table, :source_id, :category, :payload, :created_at) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("source_table") String sourceTable,
                                   @Param("source_id") String sourceId,
                                   @Param("category") String category,
                                   @Param("payload") String payload,
                                   @Param("created_at") Instant createdAt);

    /** The outbox row for an effect+category, if any (the dedup natural key
     *  {@code WHERE source_table=? AND source_id=? AND category=?}). */
    Mono<NotificationOutbox> findBySourceTableAndSourceIdAndCategory(
            String sourceTable, String sourceId, String category);

    /** All outbox rows for a domain, newest last ({@code ORDER BY created_at, id}). */
    Flux<NotificationOutbox> findByDomainOrderByCreatedAtAscIdAsc(String domain);
}
