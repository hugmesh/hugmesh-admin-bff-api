package systems.hugmesh.adminbff.charactermoderation;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.notification.NotificationCursorR2dbcRepository;
import systems.hugmesh.adminbff.notification.NotificationCursorRepository;

/**
 * Per-surface federation {@code sinceId} watermark for the
 * {@link FindingActivationReconciler}, REUSING the generic
 * {@code notification_cursor (consumer, last_seen, updated_at)} table (Liquibase 062) —
 * NO new changeset. The {@code notification_cursor} table is a generic per-consumer cursor
 * (the {@link NotificationCursorRepository} javadoc calls {@code consumer} the natural key
 * and {@code last_seen} "the last outbox id <b>or watermark</b>"); the character-moderation
 * reconciler is simply two MORE consumers on that same store, keyed
 * {@value #CONSUMER_PART} / {@value #CONSUMER_STICKER}.
 *
 * <h3>Long sinceId stored as the varchar watermark</h3>
 * The federation cursor is a {@code Long} id (strict {@code id>sinceId}); it is stored as
 * its decimal string in the {@code last_seen varchar(36)} column and parsed back on read.
 * A cold start (no row) reads as {@code null} → the reconciler polls from {@code sinceId=0}.
 *
 * <h3>Advance-only-past-contiguous-success</h3>
 * {@link #advance} is called by the reconciler ONLY with the id of the LAST finding in an
 * unbroken prefix of successful pushes (it stops at the first failure). Because the sink is
 * idempotent and the federation read is a strict {@code id>sinceId} cursor, a halted-then-
 * retried tick re-polls the failed id (and everything after) next tick; re-pushing the
 * already-applied earlier rows is harmless.
 */
@Repository
public class FindingCursorRepository {

    /** Consumer key for the character-part resolved-findings cursor. */
    public static final String CONSUMER_PART = "character-part-finding";
    /** Consumer key for the character-sticker resolved-findings cursor. */
    public static final String CONSUMER_STICKER = "character-sticker-finding";

    private final NotificationCursorRepository cursor;

    public FindingCursorRepository(NotificationCursorR2dbcRepository repo) {
        this.cursor = new NotificationCursorRepository(repo);
    }

    /** The last successfully-pushed federation finding id for a consumer, or {@code null}
     *  (cold start → poll from sinceId 0). A non-numeric stored value is treated as cold
     *  start (defensive; never written by this code). */
    public Mono<Long> find(String consumer) {
        return cursor.find(consumer).mapNotNull(s -> {
            try {
                return Long.valueOf(s);
            } catch (NumberFormatException e) {
                return null;
            }
        });
    }

    /** UPSERT the watermark for a consumer to {@code lastSeenId} (the id of the last
     *  contiguously-successful push). */
    public Mono<Void> advance(String consumer, long lastSeenId) {
        return cursor.advance(consumer, Long.toString(lastSeenId));
    }
}
