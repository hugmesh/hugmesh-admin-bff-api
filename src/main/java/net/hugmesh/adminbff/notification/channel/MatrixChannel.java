package net.hugmesh.adminbff.notification.channel;

import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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
 *
 * <h3>Real transport (second gate)</h3>
 * When {@code notify.matrix.dm.wired=true} (default false) the channel is built with a
 * {@link MatrixSystemDmClient} and sends over the standard Matrix client-server API as the
 * {@code @system} account instead of going through the stubbed admin seam. That path needs
 * no {@code homeserver.admin.enabled}: a DM is a client action, not an admin-room command.
 * Availability is then {@code notify.matrix.enabled} AND the {@code @system} token.
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns these singleton collaborators and they are never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class MatrixChannel implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(MatrixChannel.class);

    public static final String NAME = "matrix";

    private final HomeserverAdminClient homeserver;
    private final boolean enabled;
    private final boolean systemTokenPresent;
    @Nullable
    private final MatrixSystemDmClient dm;

    /**
     * @param homeserver         the existing tuwunel/akkoma admin seam (reused)
     * @param enabled            the {@code notify.matrix.enabled} feature gate
     * @param systemTokenPresent whether the {@code @system} Matrix token is configured
     *                           (Vault via ESO); false ⇒ channel reports unavailable
     */
    public MatrixChannel(HomeserverAdminClient homeserver, boolean enabled, boolean systemTokenPresent) {
        this(homeserver, enabled, systemTokenPresent, null);
    }

    /**
     * @param dm the real Matrix client-server transport, or null to stay on the stubbed
     *           admin seam ({@code notify.matrix.dm.wired=false})
     */
    public MatrixChannel(HomeserverAdminClient homeserver, boolean enabled, boolean systemTokenPresent,
                         @Nullable MatrixSystemDmClient dm) {
        this.homeserver = homeserver;
        this.enabled = enabled;
        this.systemTokenPresent = systemTokenPresent;
        this.dm = dm;
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
        boolean seam = dm != null || homeserver.enabled();
        boolean ready = enabled && seam && systemTokenPresent;
        return Mono.just(ready);
    }

    @Override
    public Mono<ChannelOutcome> send(String domain, String recipientSubject, ChannelMessage message) {
        String localpart = localpartOf(recipientSubject);
        if (localpart.isBlank()) {
            return Mono.just(ChannelOutcome.SKIPPED);
        }
        String body = message.title() + "\n\n" + (message.body() == null ? "" : message.body());
        if (dm != null) {
            // outcome mapping (FAILED to retry, SKIPPED for a missing account) is on MatrixSystemDmClient.
            return dm.sendDirectMessage(localpart, body, message.deliveryKey());
        }
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
