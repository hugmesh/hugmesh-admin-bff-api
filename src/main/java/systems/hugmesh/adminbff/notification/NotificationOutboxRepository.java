package systems.hugmesh.adminbff.notification;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code notification_outbox} — the transactional-outbox
 * spine (schema in Liquibase {@code db/changelog/062-notification-outbox.xml}).
 *
 * <p>Backed by the Spring Data {@link NotificationOutboxR2dbcRepository} interface
 * (no raw {@code DatabaseClient}); this facade keeps the public API the consumers
 * (SuspensionService transactional-outbox write, FeatureNotificationService,
 * NotificationKafkaConsumer, the test slices) depend on.
 *
 * <p>{@link #insert} returns the {@code Mono<Long>} rows-updated (1) so the caller can
 * compose it into the SAME reactive transaction as the effect write — the connection
 * is taken from the active transaction context, so a rollback of the effect rolls the
 * outbox INSERT back too (and vice versa). The reads exist for the tests + the later
 * consumer (PR4); nothing in production reads them yet.
 */
@Repository
public class NotificationOutboxRepository {

    private final NotificationOutboxR2dbcRepository repo;

    public NotificationOutboxRepository(NotificationOutboxR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * INSERT one outbox row (app-generated id), returning the rows-updated count (1) so
     * the caller can chain it into an active transaction. Subscribed INSIDE the effect's
     * reactive transaction so the INSERT is atomic with the effect write (lossless
     * transactional outbox).
     */
    public Mono<Long> insert(String domain, String sourceTable, String sourceId,
                             String category, String payload) {
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id reads it back. created_at is stamped now (the original now()
        // server default). A duplicate natural key surfaces the UNIQUE-violation (no ON
        // CONFLICT) — insertIfAbsent maps that to 0; thenReturn(1L) keeps the fresh signal.
        return repo.insertReturningId(domain, sourceTable, sourceId, category, payload, Instant.now())
                .thenReturn(1L);
    }

    /**
     * INSERT one outbox row IDEMPOTENTLY on the {@code (source_table, source_id, category)}
     * natural key (Notifications PR7 — the Kafka fast-path). Returns the rows-updated count
     * with the {@code UNIQUE(source_table, source_id, category)} violation mapped to
     * {@code 0} (the effect already has an outbox row).
     */
    public Mono<Long> insertIfAbsent(String domain, String sourceTable, String sourceId,
                                     String category, String payload) {
        return insert(domain, sourceTable, sourceId, category, payload)
                .onErrorResume(NotificationOutboxRepository::isDuplicate, e -> Mono.just(0L));
    }

    private static boolean isDuplicate(Throwable e) {
        // A unique-constraint violation surfaces as an R2DBC DataIntegrityViolation; match
        // on the type name + the canonical messages so it works on both H2 and Postgres
        // without a hard dependency on a driver-specific exception class.
        for (Throwable t = e; t != null; t = t.getCause()) {
            String n = t.getClass().getName();
            if (n.contains("DataIntegrityViolation") || n.contains("R2dbcDataIntegrityViolation")) {
                return true;
            }
            String m = t.getMessage();
            if (m != null) {
                String lm = m.toLowerCase();
                if (lm.contains("unique") || lm.contains("duplicate")
                        || lm.contains("uq_notification_outbox_source")) {
                    return true;
                }
            }
        }
        return false;
    }

    /** The outbox row for an effect+category, if any (the dedup natural key). */
    public Mono<NotificationOutbox> findBySource(String sourceTable, String sourceId, String category) {
        return repo.findBySourceTableAndSourceIdAndCategory(sourceTable, sourceId, category);
    }

    /** All outbox rows for a domain (newest last by created_at). */
    public Flux<NotificationOutbox> byDomain(String domain) {
        return repo.findByDomainOrderByCreatedAtAscIdAsc(domain);
    }

    /** Total outbox row count (test/diagnostic helper). */
    public Mono<Long> count() {
        return repo.count();
    }
}
