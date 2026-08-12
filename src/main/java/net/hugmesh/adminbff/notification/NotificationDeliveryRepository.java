package net.hugmesh.adminbff.notification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code notification_delivery} — the per-channel
 * exactly-once sent guard (schema in Liquibase {@code 062-notification-outbox.xml}).
 *
 * <p>Backed by the Spring Data {@link NotificationDeliveryR2dbcRepository} interface
 * (no raw {@code DatabaseClient}); this facade keeps the public API the reconcilers +
 * test slices depend on. The {@code UNIQUE(outbox_id, channel)} guard is the
 * idempotency primitive — a duplicate INSERT is swallowed (treated as 0 rows).
 */
@Repository
public class NotificationDeliveryRepository {

    private static final Logger log = LoggerFactory.getLogger(NotificationDeliveryRepository.class);

    /** The in-app SQL-tail reconciler's channel. */
    public static final String CHANNEL_IN_APP = "in-app";

    /** Lifecycle statuses (matches the 062 CHECK constraint plus the app-level meanings). */
    public static final String STATUS_SENT = "sent";
    public static final String STATUS_SKIPPED = "skipped";
    public static final String STATUS_FAILED = "failed";

    private final NotificationDeliveryR2dbcRepository repo;

    public NotificationDeliveryRepository(NotificationDeliveryR2dbcRepository repo) {
        this.repo = repo;
    }

    /** The oldest in-app-UNDELIVERED outbox rows, capped at {@code limit}, oldest-first. */
    public Flux<NotificationOutbox> findUndeliveredInApp(String cursorLastSeenId, int limit) {
        return findUndelivered(CHANNEL_IN_APP, cursorLastSeenId, limit);
    }

    /** The oldest CHANNEL-undelivered outbox rows, capped at {@code limit}, oldest-first. */
    public Flux<NotificationOutbox> findUndelivered(String channel, String cursorLastSeenId, int limit) {
        Flux<NotificationOutbox> rows = (cursorLastSeenId == null)
                ? repo.findUndeliveredCold(channel)
                : repo.findUndeliveredFromCursor(channel, cursorLastSeenId);
        return rows.take(limit);
    }

    /** INSERT one {@code in-app} delivery row for an outbox row, idempotently. */
    public Mono<Long> recordInApp(String outboxId, String status) {
        return record(outboxId, CHANNEL_IN_APP, status);
    }

    /** INSERT one delivery row for an outbox row on an arbitrary {@code channel},
     *  idempotently — {@code UNIQUE(outbox_id, channel)} violation maps to {@code 0}. */
    public Mono<Long> record(String outboxId, String channel, String status) {
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id reads it back. sent_at is stamped now (the original now() server
        // default). A duplicate (outbox_id, channel) surfaces the UNIQUE-violation, swallowed
        // below → idempotent (0 rows), exactly as before.
        return repo.insertReturningId(outboxId, channel, status, Instant.now())
                .thenReturn(1L)
                .onErrorResume(NotificationDeliveryRepository::isDuplicate, e -> {
                    // UNIQUE(outbox_id, channel): a concurrent pod / a re-tick already
                    // recorded this delivery. Swallow → idempotent (treated as 0 rows).
                    log.debug("[notify-reconcile] delivery for outbox={} channel={} "
                            + "already recorded (idempotent): {}", outboxId, channel, e.toString());
                    return Mono.just(0L);
                });
    }

    /** The recorded status for an outbox row's delivery on a channel, or null (tests). */
    public Mono<String> status(String outboxId, String channel) {
        return repo.findByOutboxIdAndChannel(outboxId, channel).map(NotificationDelivery::status);
    }

    /** Whether an {@code in-app} delivery row exists for an outbox row (tests/diagnostics). */
    public Mono<Boolean> existsInApp(String outboxId) {
        return repo.existsByOutboxIdAndChannel(outboxId, CHANNEL_IN_APP);
    }

    /** The recorded status for an outbox row's in-app delivery, or null (tests/diagnostics). */
    public Mono<String> statusInApp(String outboxId) {
        return status(outboxId, CHANNEL_IN_APP);
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
                        || lm.contains("uq_notification_delivery_channel")) {
                    return true;
                }
            }
        }
        return false;
    }
}
