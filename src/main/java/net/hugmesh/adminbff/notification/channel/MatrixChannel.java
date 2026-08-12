package net.hugmesh.adminbff.notification.channel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.homeserver.HomeserverOutcome;

/**
 * Matrix (tuwunel) channel adapter for the {@code @system} sender (Notifications PR5).
 * Posts a neutral DM to the recipient via the EXISTING {@link HomeserverAdminClient}
 * tuwunel admin-room mTLS-sidecar seam ({@link HomeserverAdminClient#sendSystemDirectMessage}).
 *
 * <h3>Ships dark</h3>
 * Gated on {@code notify.matrix.enabled} (default false). Even when the FEATURE gate is
 * on, {@link #available(String)} requires the homeserver admin seam itself to be enabled
 * ({@code homeserver.admin.enabled}) AND the {@code @system} Matrix token to be present —
 * so a tuwunel-less / Vault-less environment reports the channel UNAVAILABLE and the
 * reconciler skips it (retried next tick), never hard-failing. The underlying
 * {@code sendSystemDirectMessage} is itself STUBBED until the confirmed tuwunel DM verb is
 * wired, so a STUBBED outcome is treated as a transient skip (FAILED → retry) rather than
 * a false {@code sent}.
 */
public class MatrixChannel implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(MatrixChannel.class);

    public static final String NAME = "matrix";

    private final HomeserverAdminClient homeserver;
    private final boolean enabled;
    private final boolean systemTokenPresent;

    /**
     * @param homeserver         the existing tuwunel/akkoma admin seam (reused)
     * @param enabled            the {@code notify.matrix.enabled} feature gate
     * @param systemTokenPresent whether the {@code @system} Matrix token is configured
     *                           (Vault via ESO); false ⇒ channel reports unavailable
     */
    public MatrixChannel(HomeserverAdminClient homeserver, boolean enabled, boolean systemTokenPresent) {
        this.homeserver = homeserver;
        this.enabled = enabled;
        this.systemTokenPresent = systemTokenPresent;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public boolean enabled() {
        return enabled;
    }

    @Override
    public Mono<Boolean> available(String domain) {
        // Capability (the tuwunel admin seam is on for this cluster/domain) AND the
        // @system credential present. No per-domain federation probe yet — the homeserver
        // seam is cluster-wide; PR7 layers the per-domain federation-capability consult.
        boolean ready = enabled && homeserver.enabled() && systemTokenPresent;
        return Mono.just(ready);
    }

    @Override
    public Mono<ChannelOutcome> send(String domain, String recipientSubject, ChannelMessage message) {
        String localpart = localpartOf(recipientSubject);
        if (localpart.isBlank()) {
            return Mono.just(ChannelOutcome.SKIPPED);
        }
        String body = message.title() + "\n\n" + (message.body() == null ? "" : message.body());
        return homeserver.sendSystemDirectMessage(localpart, body)
                .map(MatrixChannel::toOutcome)
                .onErrorResume(e -> {
                    log.warn("[notify-matrix] DM to '{}' failed (retry next tick): {}",
                            localpart, e.toString());
                    return Mono.just(ChannelOutcome.FAILED);
                });
    }

    /** STUBBED (seam not wired) and degraded both become a transient FAILED → retry; only
     *  a real OK is a terminal {@code sent}. */
    private static ChannelOutcome toOutcome(HomeserverOutcome o) {
        return o.isOk() ? ChannelOutcome.SENT : ChannelOutcome.FAILED;
    }

    /** Derive the Matrix localpart from a Casdoor subject: drop an {@code org/} prefix and
     *  any {@code @domain} suffix, lower-cased (a tuwunel localpart can carry neither). */
    static String localpartOf(String subject) {
        if (subject == null) {
            return "";
        }
        String s = subject.trim().toLowerCase();
        int slash = s.lastIndexOf('/');
        if (slash >= 0) {
            s = s.substring(slash + 1);
        }
        int at = s.indexOf('@');
        if (at > 0) {
            s = s.substring(0, at);
        }
        return s;
    }
}
