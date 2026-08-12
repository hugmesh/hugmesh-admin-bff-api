package net.hugmesh.adminbff.notification;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code notification_cursor} — the per-consumer delivery
 * cursor (schema in Liquibase {@code 062-notification-outbox.xml}:
 * {@code (consumer, last_seen, updated_at)}, consumer is the natural key). The
 * {@link NotificationReconciler}'s {@code in-app} consumer is the FIRST writer (PR2
 * shipped it dark / schema-only).
 *
 * <p><b>The cursor is a fast-forward HINT, not the delivery truth.</b> The delivery
 * truth is {@code notification_delivery} (one row per outbox row per channel); the
 * cursor only records how far the consumer has scanned so a later tick can skip the
 * already-recorded prefix cheaply. It is therefore ADVANCED ONLY past a contiguous
 * delivered prefix — the reconciler advances {@code last_seen} to the newest outbox row
 * it has just recorded a delivery for ONLY when every row up to it is delivered, so a
 * row whose delivery failed (recorded nothing) is never skipped: the LEFT JOIN ... IS
 * NULL re-selects it next tick even when the cursor sits at or after it.
 *
 * <p>{@code last_seen} holds the outbox {@code id} of the last fully-processed row
 * (exactly the column's PR2-designed semantics + its {@code varchar(36)} width — an
 * outbox UUID). The delivery query resolves that id's {@code created_at} via a subselect
 * when fast-forwarding, so the cursor stays a single-id watermark and the schema is NOT
 * widened.
 */
@Repository
public class NotificationCursorRepository {

    /** The reconciler's consumer name (the in-app SQL-tail backstop). */
    public static final String CONSUMER_IN_APP = "in-app";

    private final NotificationCursorR2dbcRepository repo;

    public NotificationCursorRepository(NotificationCursorR2dbcRepository repo) {
        this.repo = repo;
    }

    /** The last fully-processed outbox id for a consumer, or null (cold start). */
    public Mono<String> find(String consumer) {
        return repo.findById(consumer).map(NotificationCursor::lastSeen);
    }

    /**
     * UPSERT the watermark for a consumer to the outbox {@code id} of the last
     * fully-processed row. A portable {@code existsById}-then-save (INSERT if absent,
     * UPDATE if present) — behaviour-identical to the prior UPDATE-then-INSERT.
     */
    public Mono<Void> advance(String consumer, String lastSeenId) {
        return repo.existsById(consumer)
                .flatMap(exists -> repo.save(NotificationCursor.of(consumer, lastSeenId, !exists)))
                .then();
    }
}
