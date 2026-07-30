package systems.hugmesh.adminbff.notification.channel;

import reactor.core.publisher.Mono;

/**
 * A per-channel EXTERNAL notification adapter (Matrix / email / Akkoma / phpBB) that the
 * {@code ExternalChannelReconciler} fans an outbox row out to, posting as the neutral
 * per-domain {@code @system} sender (Notifications PR5/PR7).
 *
 * <h3>Ships dark + degrade-on-absence (the cross-cutting channel contract)</h3>
 * <ul>
 *   <li>{@link #enabled()} — the channel-level feature gate ({@code notify.<channel>
 *       .enabled}, default false). A disabled channel is never even consulted.</li>
 *   <li>{@link #available(String)} — per-domain readiness: the federation capability for
 *       that domain (is the homeserver/email present?) AND the {@code @system} channel
 *       credential being present in Vault. An UNAVAILABLE channel is SKIPPED for this tick
 *       (the reconciler records nothing and retries next tick) — it does NOT hard-fail and
 *       does NOT block other channels.</li>
 *   <li>{@link #send} — NEVER throws: a transport error resolves to
 *       {@link ChannelOutcome#FAILED} (record nothing, retry) so a down channel degrades
 *       to a retry rather than a lost notification or a crashed tick.</li>
 * </ul>
 *
 * <h3>Neutral sender — no actor, ever</h3>
 * {@link #send} receives only the neutral {@code title}/{@code body} the
 * {@code NotificationTemplate} composed from the outbox payload (which by the PR2 outbox
 * invariant carries reason/ttl/target but NEVER the acting mod/admin identity), plus the
 * recipient subject. An adapter has no access to — and must never surface — who took the
 * action.
 */
public interface NotificationChannel {

    /** The channel name as recorded in {@code notification_delivery.channel} (e.g.
     *  {@code matrix}, {@code email}). Also the channel's cursor consumer name. */
    String name();

    /** Whether this channel's feature gate is on ({@code notify.<channel>.enabled}). A
     *  disabled channel contributes no reconciler consumer at all. */
    boolean enabled();

    /**
     * Whether the channel can deliver for {@code domain} RIGHT NOW: the per-domain
     * capability is present AND the {@code @system} credential is configured. False ⇒ the
     * reconciler SKIPS this row for this channel this tick (records nothing, retries).
     */
    Mono<Boolean> available(String domain);

    /**
     * Post one neutral notification to {@code recipientSubject} in {@code domain} as the
     * {@code @system} sender. Never throws — maps any failure to
     * {@link ChannelOutcome#FAILED}.
     */
    Mono<ChannelOutcome> send(String domain, String recipientSubject, ChannelMessage message);
}
