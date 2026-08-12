package net.hugmesh.adminbff.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.lease.LeaderElection;
import net.hugmesh.adminbff.notification.channel.ChannelMessage;
import net.hugmesh.adminbff.notification.channel.NotificationChannel;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The EXTERNAL-CHANNEL fan-out reconciler (Notifications PR5/PR7): a {@code @Scheduled}
 * SQL-tail that fans each {@code notification_outbox} row out to the per-domain
 * {@code @system} sender's PERSONAL channels (Matrix DM / email — PR5; Akkoma / phpBB —
 * PR7), each its own independent {@code notification_delivery} channel + cursor.
 *
 * <p>It is the SIBLING of {@link NotificationReconciler} (the in-app SQL-tail): SAME
 * outbox, SAME never-hard-fail / poison-dead-letter / contiguous-cursor / multi-pod
 * idempotency story, but ONE consumer + delivery channel PER {@link NotificationChannel}
 * instead of the single {@code in-app} channel. The two never collide — they write
 * different {@code notification_delivery.channel} rows.
 *
 * <h3>Per-channel, ships-dark, degrade-on-absence</h3>
 * Only channels whose {@link NotificationChannel#enabled()} gate is on participate (a
 * disabled channel — the default — contributes no work). For an enabled channel, each row
 * is delivered ONLY when {@link NotificationChannel#available(String)} is true for the
 * row's domain (capability present + {@code @system} credential present); otherwise the
 * row is SKIPPED for this tick (records nothing, cursor not advanced past it) and retried
 * next tick — the outbox→partial, retried-next-tick degrade.
 *
 * <h3>account-restriction forced-on the personal channels</h3>
 * {@code account-restriction} (a ban/timeout/unban) is a forced-on category — it is
 * always attempted on every available personal channel regardless of any silence
 * preference, because a user MUST learn their access changed (the appeal path depends on
 * it). Other categories are delivered the same way here today; the user-silenceable
 * gating lives on the in-app path (user-bff prefs) and is layered on the external
 * channels by PR7's preference consult — see the PR7 follow-up.
 *
 * <h3>Neutral sender</h3>
 * The title/body handed to each adapter come from {@link NotificationTemplate} (composed
 * from the outbox payload's reason/ttl, NEVER the actor), so the {@code @system} voice is
 * impersonal on every channel.
 */
@Service
public class ExternalChannelReconciler {

    private static final Logger log = LoggerFactory.getLogger(ExternalChannelReconciler.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final NotificationDeliveryRepository deliveries;
    private final NotificationCursorRepository cursor;
    private final List<NotificationChannel> channels;
    private final LeaderElection leader;
    private final MeterRegistry meters;
    private final int batchSize;
    private final int maxAttempts;

    /** Per-(channel,row) failure counter (in-memory) — bounds poison-row retries. */
    private final ConcurrentHashMap<String, Integer> attempts = new ConcurrentHashMap<>();

    public ExternalChannelReconciler(NotificationDeliveryRepository deliveries,
                                     NotificationCursorRepository cursor,
                                     List<NotificationChannel> channels,
                                     LeaderElection leader,
                                     MeterRegistry meters,
                                     @Value("${notification.reconcile.batch-size:100}") int batchSize,
                                     @Value("${notification.reconcile.max-attempts:5}") int maxAttempts) {
        this.deliveries = deliveries;
        this.cursor = cursor;
        this.channels = channels == null ? List.of() : channels;
        this.leader = leader;
        this.meters = meters;
        this.batchSize = batchSize;
        this.maxAttempts = maxAttempts;
    }

    @Scheduled(
            fixedDelayString = "${notification.reconcile.interval-ms:10000}",
            initialDelayString = "${notification.reconcile.external-initial-delay-ms:20000}")
    public void runTick() {
        runOnce()
                .onErrorResume(e -> {
                    meters.counter("notification.external.tick_errors").increment();
                    log.warn("[notify-external] tick error (swallowed): {}", e.toString());
                    return Mono.empty();
                })
                .subscribe();
    }

    /** One reconcile pass over every ENABLED channel. Never errors out of the chain. */
    public Mono<Void> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[notify-external] not leader ({}) — skipping tick", leader.label());
            return Mono.empty();
        }
        return Flux.fromIterable(channels)
                .filter(NotificationChannel::enabled)
                .concatMap(ch -> drainChannel(ch)
                        .onErrorResume(e -> {
                            meters.counter("notification.external.channel_errors", "channel", ch.name()).increment();
                            log.warn("[notify-external] channel {} drain error (swallowed): {}",
                                    ch.name(), e.toString());
                            return Mono.empty();
                        }))
                .then();
    }

    /** Drain the undelivered batch for ONE channel, advancing that channel's cursor over
     *  the contiguous delivered prefix. */
    private Mono<Void> drainChannel(NotificationChannel ch) {
        String consumer = consumerFor(ch);
        return cursor.find(consumer)
                .flatMap(wm -> drain(ch, consumer, wm).then(Mono.just(Boolean.TRUE)))
                .switchIfEmpty(Mono.defer(() -> drain(ch, consumer, null).then(Mono.just(Boolean.TRUE))))
                .then();
    }

    private Mono<Void> drain(NotificationChannel ch, String consumer, String wmId) {
        AtomicReference<String> advanceTo = new AtomicReference<>(null);
        AtomicReference<Boolean> prefixIntact = new AtomicReference<>(Boolean.TRUE);
        return deliveries.findUndelivered(ch.name(), wmId, batchSize)
                .concatMap(row -> processRow(ch, row, advanceTo, prefixIntact))
                .then(Mono.defer(() -> {
                    String to = advanceTo.get();
                    return to == null ? Mono.empty() : cursor.advance(consumer, to);
                }));
    }

    /** Process ONE outbox row for ONE channel: availability gate → send → record. Never
     *  errors (per-row failure is metered + skipped so the batch keeps draining). */
    private Mono<Void> processRow(NotificationChannel ch, NotificationOutbox row,
                                  AtomicReference<String> advanceTo,
                                  AtomicReference<Boolean> prefixIntact) {
        // Gate on channel availability, render and send, then record the delivery outcome.
        return ch.available(row.domain())
                .flatMap(available -> deliverIfAvailable(available, ch, row, advanceTo, prefixIntact))
                .onErrorResume(e -> {
            meters.counter("notification.external.row_errors", "channel", ch.name()).increment();
            log.warn("[notify-external] {} row {} errored (metered, skipped): {}",
                    ch.name(), row.id(), e.toString());
            prefixIntact.set(Boolean.FALSE);
            return Mono.empty();
        });
    }

    /** Skip unavailable channels; otherwise resolve recipient + send + record outcome. */
    private Mono<Void> deliverIfAvailable(Boolean available, NotificationChannel ch,
                                           NotificationOutbox row,
                                           AtomicReference<String> advanceTo,
                                           AtomicReference<Boolean> prefixIntact) {
        if (!Boolean.TRUE.equals(available)) {
            // Channel not ready for this domain: SKIP this row for this tick.
            meters.counter("notification.external.unavailable", "channel", ch.name()).increment();
            prefixIntact.set(Boolean.FALSE);
            log.debug("[notify-external] {} unavailable for domain={}; skip row {} this tick",
                    ch.name(), row.domain(), row.id());
            return Mono.empty();
        }
        String recipient = targetSubject(row.payload());
        if (recipient == null || recipient.isBlank()) {
            // Un-buildable (no recipient): poison → dead-letter path.
            return onFailure(ch, row, advanceTo, prefixIntact, "no-recipient");
        }
        NotificationTemplate.Message msg = NotificationTemplate.render(row.category(), row.payload());
        ChannelMessage cm = new ChannelMessage(row.category(), msg.title(), msg.body());
        return ch.send(row.domain(), recipient, cm).flatMap(outcome -> switch (outcome) {
            case SENT -> onTerminal(ch, row, advanceTo, prefixIntact,
                    NotificationDeliveryRepository.STATUS_SENT, "sent");
            case SKIPPED -> onTerminal(ch, row, advanceTo, prefixIntact,
                    NotificationDeliveryRepository.STATUS_SKIPPED, "skipped");
            case FAILED -> onFailure(ch, row, advanceTo, prefixIntact, "send-failed");
        });
    }

    /** Record a terminal per-channel delivery (sent/skipped); clear attempts; maybe advance. */
    private Mono<Void> onTerminal(NotificationChannel ch, NotificationOutbox row,
                                  AtomicReference<String> advanceTo,
                                  AtomicReference<Boolean> prefixIntact,
                                  String status, String meterSuffix) {
        return deliveries.record(row.id(), ch.name(), status)
                .doOnSuccess(r -> {
                    meters.counter("notification.external." + meterSuffix, "channel", ch.name()).increment();
                    attempts.remove(key(ch, row));
                    if (Boolean.TRUE.equals(prefixIntact.get())) {
                        advanceTo.set(row.id());
                    }
                }).then();
    }

    /** A failed/unbuildable attempt: bump the attempt counter; dead-letter after N. */
    private Mono<Void> onFailure(NotificationChannel ch, NotificationOutbox row,
                                 AtomicReference<String> advanceTo,
                                 AtomicReference<Boolean> prefixIntact, String why) {
        int n = attempts.merge(key(ch, row), 1, Integer::sum);
        if (n >= maxAttempts) {
            meters.counter("notification.external.dead_lettered", "channel", ch.name()).increment();
            attempts.remove(key(ch, row));
            log.warn("[notify-external] {} row {} dead-lettered after {} attempts ({})",
                    ch.name(), row.id(), n, why);
            return deliveries.record(row.id(), ch.name(), NotificationDeliveryRepository.STATUS_FAILED)
                    .doOnSuccess(r -> {
                        if (Boolean.TRUE.equals(prefixIntact.get())) {
                            advanceTo.set(row.id());
                        }
                    }).then();
        }
        meters.counter("notification.external.failed", "channel", ch.name()).increment();
        prefixIntact.set(Boolean.FALSE);
        log.debug("[notify-external] {} row {} attempt {} failed ({}); retry next tick",
                ch.name(), row.id(), n, why);
        return Mono.empty();
    }

    /** The cursor consumer name for a channel — namespaced so it never collides with the
     *  in-app reconciler's {@code in-app} consumer or another channel's. */
    static String consumerFor(NotificationChannel ch) {
        return "ext:" + ch.name();
    }

    private static String key(NotificationChannel ch, NotificationOutbox row) {
        return ch.name() + "|" + row.id();
    }

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
}
