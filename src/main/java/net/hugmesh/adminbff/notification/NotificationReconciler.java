package net.hugmesh.adminbff.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The Notifications PR4 part-B ENGINE: a {@code @Scheduled} SQL-tail reconciler that
 * tails {@code notification_outbox} for {@code in-app}-undelivered rows and delivers each
 * to user-bff's internal in-app notification endpoint (part A's contract), recording the
 * outcome in {@code notification_delivery}. IN-APP ONLY — no Matrix/Akkoma/email here
 * (those channels are separate consumers; this engine writes exactly the {@code in-app}
 * delivery row).
 *
 * <h3>The tick (oldest-first, bounded batch)</h3>
 * <ol>
 *   <li>Single-writer cheap-path via {@link LeaderElection} (same primitive the
 *       suspension expiry loop uses). NOTE: leadership is an optimisation, NOT a
 *       correctness requirement — see "Multi-pod safety" below.</li>
 *   <li>Select the oldest {@code in-app}-undelivered outbox rows (LEFT JOIN
 *       notification_delivery on outbox_id AND channel='in-app' WHERE delivery IS NULL),
 *       fast-forwarded past the {@code in-app} cursor watermark, capped at the batch
 *       size.</li>
 *   <li>For each row, in created_at,id order: parse payload -> target userSubject +
 *       category + reason/ttl; build a NEUTRAL title+body from
 *       {@link NotificationTemplate} (never an actor identity); call user-bff via
 *       {@link UserBffNotificationClient}.</li>
 *   <li>On the call's success (DELIVERED or SUPPRESSED) INSERT
 *       {@code notification_delivery(in-app, sent|skipped)} — the
 *       {@code UNIQUE(outbox_id, channel)} guard makes a re-tick a no-op (duplicate
 *       insert swallowed). On call FAILURE record NOTHING and STOP advancing the cursor
 *       past this row (it is retried next tick).</li>
 *   <li>Advance the {@code in-app} cursor watermark to the NEWEST row whose delivery is
 *       recorded in this batch's contiguous delivered prefix — never past a row that
 *       failed (the LEFT JOIN re-selects undelivered rows regardless, the cursor is only
 *       a fast-forward hint).</li>
 * </ol>
 *
 * <h3>never-hard-fail + poison-row dead-letter</h3>
 * Every per-row error is caught + metered (Micrometer counters); the tick never throws
 * out of {@code @Scheduled}. A POISON row (the call keeps FAILING, or the row can't be
 * built — e.g. no target subject) is retried up to {@link #maxAttempts} times across
 * ticks (an in-memory per-row attempt counter); on the (N+1)th failure it is
 * DEAD-LETTERED — a {@code notification_delivery(in-app, 'failed')} row is written and
 * the cursor advances past it — so a single bad row can never head-of-line-block the
 * backlog forever.
 *
 * <h3>Multi-pod safety (no leader required for correctness)</h3>
 * admin-bff may run multiple replicas. Leadership here is a cost optimisation (one pod
 * does the scan); CORRECTNESS rests on two idempotency guards that hold even if two pods
 * tick the same row concurrently: (1) the {@code UNIQUE(outbox_id, 'in-app')} delivery
 * constraint means at most ONE in-app delivery row per outbox row ever exists — the
 * loser's duplicate insert is swallowed by {@link NotificationDeliveryRepository}; and
 * (2) part A keys on the deterministic {@code (sourceTable, sourceId)} so a duplicate
 * user-bff call is idempotent there too. So concurrent pods produce at most one delivery
 * + at most one user-perceived notification.
 */
@Service
public class NotificationReconciler {

    private static final Logger log = LoggerFactory.getLogger(NotificationReconciler.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final NotificationDeliveryRepository deliveries;
    private final NotificationCursorRepository cursor;
    private final UserBffNotificationClient userBff;
    private final LeaderElection leader;
    private final int batchSize;
    private final int maxAttempts;

    /** Per-row failure counter (in-memory). Bounds poison-row retries before dead-letter.
     *  Bounded by the live undelivered set; entries are removed when a row terminalises. */
    private final ConcurrentHashMap<String, Integer> attempts = new ConcurrentHashMap<>();

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    // ── Micrometer counters (never-hard-fail metering) ──────────────────────
    private final Counter delivered;
    private final Counter suppressed;
    private final Counter failed;       // a single failed attempt (will retry)
    private final Counter deadLettered; // a poison row exhausted its attempts
    private final Counter tickErrors;   // an unexpected tick-level error (still swallowed)

    public NotificationReconciler(NotificationDeliveryRepository deliveries,
                                  NotificationCursorRepository cursor,
                                  UserBffNotificationClient userBff,
                                  LeaderElection leader,
                                  MeterRegistry meters,
                                  @Value("${notification.reconcile.batch-size:100}") int batchSize,
                                  @Value("${notification.reconcile.max-attempts:5}") int maxAttempts) {
        this.deliveries = deliveries;
        this.cursor = cursor;
        this.userBff = userBff;
        this.leader = leader;
        this.batchSize = batchSize;
        this.maxAttempts = maxAttempts;
        this.delivered = Counter.builder("notification.reconcile.delivered")
                .description("in-app notifications delivered by the reconciler").register(meters);
        this.suppressed = Counter.builder("notification.reconcile.suppressed")
                .description("in-app notifications suppressed (recipient silenced / gate off)").register(meters);
        this.failed = Counter.builder("notification.reconcile.failed")
                .description("in-app delivery attempts that failed (will retry next tick)").register(meters);
        this.deadLettered = Counter.builder("notification.reconcile.dead_lettered")
                .description("poison rows dead-lettered after exhausting retry attempts").register(meters);
        this.tickErrors = Counter.builder("notification.reconcile.tick_errors")
                .description("unexpected reconcile-tick errors (swallowed; tick never hard-fails)").register(meters);
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${notification.reconcile.interval-ms:10000}",
            initialDelayString = "${notification.reconcile.initial-delay-ms:15000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                // Belt-and-braces: runOnce already swallows, but a @Scheduled method must
                // never let anything escape — meter + drop.
                .onErrorResume(e -> {
                    tickErrors.increment();
                    log.warn("[notify-reconcile] tick error (swallowed): {}", e.toString());
                    return Mono.empty();
                })
                .subscribe();
    }

    /**
     * One reconcile pass. Never errors (the whole chain is {@code onErrorResume}d so the
     * scheduler never sees a failure). Skips when not the leader (cost optimisation).
     */
    public Mono<Void> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[notify-reconcile] not leader ({}) — skipping tick", leader.label());
            return Mono.empty();
        }
        // cursor.find emits the last-seen id when one exists, else completes EMPTY (cold
        // start). Map it to a drain; switchIfEmpty handles the cold start.
        return cursor.find(NotificationCursorRepository.CONSUMER_IN_APP)
                .flatMap(lastSeenId -> drain(lastSeenId).then(Mono.just(Boolean.TRUE)))
                .switchIfEmpty(Mono.defer(() -> drain(null).then(Mono.just(Boolean.TRUE))))
                .then()
                .onErrorResume(e -> {
                    tickErrors.increment();
                    log.warn("[notify-reconcile] tick failed (will retry next tick): {}", e.toString());
                    return Mono.empty();
                });
    }

    /** Select the bounded batch and process it row-by-row, advancing the cursor over the
     *  contiguous delivered prefix. */
    private Mono<Void> drain(String wmId) {
        // Carry the advancing watermark (the last contiguously-delivered outbox id)
        // through the sequential per-row processing.
        AtomicReference<String> advanceTo = new AtomicReference<>(null);
        AtomicReference<Boolean> prefixIntact = new AtomicReference<>(Boolean.TRUE);
        return deliveries.findUndeliveredInApp(wmId, batchSize)
                // concatMap = strictly sequential (oldest-first) so the cursor's
                // contiguous-prefix invariant holds.
                .concatMap(row -> processRow(row, advanceTo, prefixIntact))
                .then(Mono.defer(() -> {
                    String to = advanceTo.get();
                    if (to == null) {
                        return Mono.empty();
                    }
                    return cursor.advance(NotificationCursorRepository.CONSUMER_IN_APP, to);
                }));
    }

    /**
     * Process ONE outbox row. Returns a never-erroring {@code Mono<Void>}: any per-row
     * failure is caught + metered, so {@code concatMap} keeps draining the rest of the
     * batch (no head-of-line block within a tick).
     */
    private Mono<Void> processRow(NotificationOutbox row,
                                  AtomicReference<String> advanceTo,
                                  AtomicReference<Boolean> prefixIntact) {
        // Build and deliver the in-app notification, handling poison rows and outcomes.
        return Mono.defer(() -> buildAndDeliver(row, advanceTo, prefixIntact))
                .onErrorResume(e -> {
            // Defence-in-depth: an unexpected per-row error must not break the batch.
            failed.increment();
            log.warn("[notify-reconcile] row {} errored (metered, skipped this tick): {}",
                    row.id(), e.toString());
            prefixIntact.set(Boolean.FALSE);
            return Mono.empty();
        });
    }

    /** Build the notification request and deliver it, treating un-buildable rows as poison. */
    private Mono<Void> buildAndDeliver(NotificationOutbox row,
                                        AtomicReference<String> advanceTo,
                                        AtomicReference<Boolean> prefixIntact) {
        UserBffNotification req = build(row);
        if (req == null) {
            // Un-buildable (e.g. no target subject): dead-letter instead of retrying forever.
            return onFailure(row, advanceTo, prefixIntact, "unbuildable");
        }
        return userBff.deliverInApp(req).flatMap(outcome -> switch (outcome) {
            case DELIVERED -> onSuccess(row, advanceTo, prefixIntact,
                    NotificationDeliveryRepository.STATUS_SENT, delivered);
            case SUPPRESSED -> onSuccess(row, advanceTo, prefixIntact,
                    NotificationDeliveryRepository.STATUS_SKIPPED, suppressed);
            case FAILED -> onFailure(row, advanceTo, prefixIntact, "call-failed");
        });
    }

    /** Record the terminal delivery (sent/skipped), clear the attempt counter, and — if
     *  the delivered prefix is still contiguous — advance the cursor to this row. */
    private Mono<Void> onSuccess(NotificationOutbox row,
                                 AtomicReference<String> advanceTo,
                                 AtomicReference<Boolean> prefixIntact,
                                 String status, Counter meter) {
        return deliveries.recordInApp(row.id(), status)
                .doOnSuccess(rows -> {
                    meter.increment();
                    attempts.remove(row.id());
                    maybeAdvance(row, advanceTo, prefixIntact);
                })
                .then();
    }

    /**
     * A failed delivery attempt. Bump the in-memory attempt counter; if it has now
     * EXHAUSTED {@link #maxAttempts}, DEAD-LETTER the row (write a {@code failed} delivery
     * + advance past it) so a poison row never blocks the backlog forever. Otherwise
     * record NOTHING and break the contiguous-prefix so the cursor does NOT advance past
     * this row — it is retried next tick.
     */
    private Mono<Void> onFailure(NotificationOutbox row,
                                 AtomicReference<String> advanceTo,
                                 AtomicReference<Boolean> prefixIntact,
                                 String why) {
        int n = attempts.merge(row.id(), 1, Integer::sum);
        if (n >= maxAttempts) {
            // Poison row → dead-letter: a terminal 'failed' delivery row (the
            // UNIQUE(outbox_id,'in-app') guard makes even this idempotent) so the LEFT
            // JOIN stops re-selecting it, then advance past it.
            deadLettered.increment();
            attempts.remove(row.id());
            log.warn("[notify-reconcile] row {} dead-lettered after {} attempts ({})",
                    row.id(), n, why);
            return deliveries.recordInApp(row.id(), NotificationDeliveryRepository.STATUS_FAILED)
                    .doOnSuccess(r -> maybeAdvance(row, advanceTo, prefixIntact))
                    .then();
        }
        failed.increment();
        // Break the contiguous delivered prefix: the cursor must not skip this still-
        // undelivered row. (It will be re-selected by the LEFT JOIN next tick regardless,
        // but stopping the watermark here keeps the fast-forward hint honest.)
        prefixIntact.set(Boolean.FALSE);
        log.debug("[notify-reconcile] row {} attempt {} failed ({}); retry next tick",
                row.id(), n, why);
        return Mono.empty();
    }

    /** Advance the watermark to this row ONLY while the delivered prefix is still
     *  contiguous (no earlier row in this batch failed). */
    private void maybeAdvance(NotificationOutbox row,
                              AtomicReference<String> advanceTo,
                              AtomicReference<Boolean> prefixIntact) {
        if (Boolean.TRUE.equals(prefixIntact.get())) {
            advanceTo.set(row.id());
        }
    }

    /** Build the user-bff request from an outbox row. Returns null when the target
     *  subject can't be resolved (an un-buildable / poison row). */
    UserBffNotification build(NotificationOutbox row) {
        String userSubject = targetSubject(row.payload());
        if (userSubject == null || userSubject.isBlank()) {
            return null;
        }
        NotificationTemplate.Message msg = NotificationTemplate.render(row.category(), row.payload());
        return new UserBffNotification(
                row.domain(),
                userSubject,
                row.category(),
                msg.title(),
                msg.body(),
                row.sourceTable(),
                row.sourceId());
    }

    /** Extract the {@code target} (the recipient Casdoor subject) from the outbox payload. */
    private static String targetSubject(String payload) {
        if (payload == null || payload.isBlank()) {
            return null;
        }
        try {
            JsonNode p = MAPPER.readTree(payload);
            JsonNode t = p.get("target");
            return (t == null || t.isNull()) ? null : t.asText();
        } catch (Exception e) {
            return null;
        }
    }

    /** Test/diagnostic snapshot of the in-memory attempt map size. */
    Map<String, Integer> attemptsView() {
        return Map.copyOf(attempts);
    }
}
