package net.hugmesh.adminbff.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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
import java.util.Map;
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
 * <h3>Preference consult (user-silenceable)</h3>
 * After the availability gate and the recipient check, and before any send, the row
 * owner's (the payload {@code target}'s) effective preferences are read from user-bff
 * ({@link UserBffNotificationClient#effectivePreferences}, {@code GET
 * /bff/user/internal/notification-preferences/{owner}?domain=}, ROLE_SERVICE bearer). The
 * read is per category and applies to every channel alike; it is made at most once per
 * (owner, domain) per tick and shared by all channels in that tick.
 * <ul>
 *   <li>Category enabled (the default; an owner with no stored rows and a category user-bff
 *       does not list both read as enabled): delivered as before.</li>
 *   <li>Category silenced: a terminal {@code skipped} delivery is recorded for that channel
 *       (metered {@code notification.external.preference_skipped}), with no send. Being
 *       terminal, the channel's cursor advances over it contiguously, exactly like a
 *       directive skip: never a poison row, never a stall.</li>
 *   <li>Lookup FAILED (transport / non-2xx / timeout / token): <b>fail CLOSED, retried</b>.
 *       Nothing is sent and nothing is recorded; the row breaks the contiguous prefix and
 *       is retried next tick (metered {@code notification.external.preference_lookup_failed}),
 *       the same degrade as an unavailable channel. A silenced user is never messaged on a
 *       guess, and a user-bff outage delays external notifications rather than losing them;
 *       it does not count toward the poison-row dead-letter. The in-app path stays the floor.
 *       The cost of that choice: a held row is never dead-lettered, so while lookups keep
 *       failing, held rows accumulate at the head of the channel's batch window, and once
 *       {@code batch-size} of them are pending, rows behind them (an
 *       {@code account-restriction} included) wait until the lookups recover. A lookup
 *       failure is expected to be uniform (user-bff down, or deployed without #36), so this
 *       is a delay rather than a loss. A per-row permanent failure is possible only if an
 *       outbox domain does not match user-bff's {@code domain} token pattern
 *       ({@code ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$}), which every {@code DomainSlug} and the
 *       {@code default} sentinel do.</li>
 *   <li>With the user-bff gate off ({@code notification.user-bff.enabled=false}, the
 *       default) no lookup is made and every category reads as enabled, the pre-consult
 *       behaviour.</li>
 * </ul>
 *
 * <h3>account-restriction forced-on the personal channels</h3>
 * {@code account-restriction} (a ban/timeout/unban) is a forced-on category — it is
 * always attempted on every available personal channel regardless of any silence
 * preference, because a user MUST learn their access changed (the appeal path depends on
 * it). The carve-out is enforced HERE, not delegated to user-bff (which also reports it
 * enabled): an account-restriction row skips the preference lookup entirely, so a stale or
 * wrong upstream answer cannot silence it, and its own delivery never waits on a lookup.
 * That is fail OPEN for this category, by construction (subject only to the batch-window
 * caveat under the lookup-failure rule above).
 *
 * <h3>Moderator channel directive</h3>
 * An outbox row may carry the moderator's {@code notify_channels} directive (see
 * {@link NotifyChannelDirective}). It is checked before the availability gate and only
 * selects a subset of the default fan-out: a channel the directive does not name records a terminal {@code skipped}
 * delivery (no send); a named channel still goes through its own {@code enabled()} /
 * {@code available()} gates, so the directive never turns a gated channel on. A
 * directive naming no enabled external channel is treated as absent, but one that names an
 * enabled channel is NOT checked against that channel's availability or recipient: if the
 * named channel is unavailable or skips the row, the others have already recorded a terminal
 * skip and no external channel delivers it (not retried). The in-app reconciler does not
 * read the directive.
 *
 * <h3>Neutral sender</h3>
 * The title/body handed to each adapter come from {@link NotificationTemplate} (composed
 * from the outbox payload's reason/ttl, NEVER the actor), so the {@code @system} voice is
 * impersonal on every channel.
 */
@Service
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
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
    private final UserBffNotificationClient userBff;

    /** The current tick's preference reads, one per (owner, domain), shared by every channel. */
    private final AtomicReference<Map<String, Mono<UserBffNotificationClient.PreferenceLookup>>> tickPreferences =
            new AtomicReference<>(new ConcurrentHashMap<>());

    /** Per-(channel,row) failure counter (in-memory) — bounds poison-row retries. */
    private final ConcurrentHashMap<String, Integer> attempts = new ConcurrentHashMap<>();

    public ExternalChannelReconciler(NotificationDeliveryRepository deliveries,
                                     NotificationCursorRepository cursor,
                                     List<NotificationChannel> channels,
                                     LeaderElection leader,
                                     MeterRegistry meters,
                                     UserBffNotificationClient userBff,
                                     @Value("${notification.reconcile.batch-size:100}") int batchSize,
                                     @Value("${notification.reconcile.max-attempts:5}") int maxAttempts) {
        this.deliveries = deliveries;
        this.cursor = cursor;
        this.channels = channels == null ? List.of() : channels;
        this.leader = leader;
        this.meters = meters;
        this.batchSize = batchSize;
        this.maxAttempts = maxAttempts;
        this.userBff = userBff;
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
        tickPreferences.set(new ConcurrentHashMap<>());
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
        // The whole body runs under ONE per-row guard (deferred, so a synchronous throw is
        // caught too): a failing record on the directive-skip path must not abort the drain
        // for the rest of the batch any more than a failing send does.
        return Mono.defer(() -> processRowUnguarded(ch, row, advanceTo, prefixIntact))
                .onErrorResume(e -> {
                    meters.counter("notification.external.row_errors", "channel", ch.name()).increment();
                    log.warn("[notify-external] {} row {} errored (metered, skipped): {}",
                            ch.name(), row.id(), e.toString());
                    prefixIntact.set(Boolean.FALSE);
                    return Mono.empty();
                });
    }

    private Mono<Void> processRowUnguarded(NotificationChannel ch, NotificationOutbox row,
                                           AtomicReference<String> advanceTo,
                                           AtomicReference<Boolean> prefixIntact) {
        // The moderator's channel directive comes BEFORE the availability gate: an
        // excluded channel records a terminal skip so its cursor moves on, instead of being
        // retried as "unavailable" forever.
        if (!NotifyChannelDirective.allows(row.payload(), ch.name(), enabledChannelNames())) {
            return onTerminal(ch, row, advanceTo, prefixIntact,
                    NotificationDeliveryRepository.STATUS_SKIPPED, "directive_skipped");
        }
        // Gate on channel availability, render and send, then record the delivery outcome.
        return ch.available(row.domain())
                .flatMap(available -> deliverIfAvailable(available, ch, row, advanceTo, prefixIntact));
    }

    /** The names of the channels whose enabled() gate is on: the only channels a directive can name. */
    private List<String> enabledChannelNames() {
        return channels.stream().filter(NotificationChannel::enabled).map(NotificationChannel::name).toList();
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
        if (NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION.equals(row.category())) {
            // FORCED-ON: never consult the preference (see the class javadoc).
            return send(ch, row, recipient, advanceTo, prefixIntact);
        }
        return preferencesFor(recipient, row.domain())
                .flatMap(prefs -> deliverIfPreferred(prefs, ch, row, recipient, advanceTo, prefixIntact));
    }

    /** Apply the owner's preference verdict: failed lookup retries, silenced skips, enabled sends. */
    private Mono<Void> deliverIfPreferred(UserBffNotificationClient.PreferenceLookup prefs,
                                          NotificationChannel ch, NotificationOutbox row, String recipient,
                                          AtomicReference<String> advanceTo,
                                          AtomicReference<Boolean> prefixIntact) {
        if (!prefs.ok()) {
            // Fail CLOSED, retried: send nothing, record nothing, hold the cursor.
            meters.counter("notification.external.preference_lookup_failed", "channel", ch.name()).increment();
            prefixIntact.set(Boolean.FALSE);
            log.debug("[notify-external] {} preference lookup failed; row {} retried next tick",
                    ch.name(), row.id());
            return Mono.empty();
        }
        if (!prefs.enabled(row.category())) {
            return onTerminal(ch, row, advanceTo, prefixIntact,
                    NotificationDeliveryRepository.STATUS_SKIPPED, "preference_skipped");
        }
        return send(ch, row, recipient, advanceTo, prefixIntact);
    }

    /** One preference read per (owner, domain) per tick, shared by every channel. */
    private Mono<UserBffNotificationClient.PreferenceLookup> preferencesFor(String owner, String domain) {
        return tickPreferences.get().computeIfAbsent(owner + "\u0000" + domain,
                k -> userBff.effectivePreferences(owner, domain).cache());
    }

    /** Render the neutral message, send it, and record the outcome. */
    private Mono<Void> send(NotificationChannel ch, NotificationOutbox row, String recipient,
                            AtomicReference<String> advanceTo,
                            AtomicReference<Boolean> prefixIntact) {
        NotificationTemplate.Message msg = NotificationTemplate.render(row.category(), row.payload());
        ChannelMessage cm = new ChannelMessage(row.category(), msg.title(), msg.body(), row.id());
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
