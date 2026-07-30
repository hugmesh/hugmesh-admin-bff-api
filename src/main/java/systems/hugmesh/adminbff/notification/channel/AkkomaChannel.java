package systems.hugmesh.adminbff.notification.channel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.announcement.AkkomaOutcome;
import systems.hugmesh.adminbff.announcement.AnnouncementMastodonClient;

/**
 * Akkoma (Mastodon-API) channel adapter for the {@code @system} sender (Notifications
 * PR7). Posts a neutral LOCAL-ONLY notice to the recipient via the EXISTING
 * {@link AnnouncementMastodonClient} akkoma seam
 * ({@link AnnouncementMastodonClient#postLocalUserNotice}) — reusing the local-only akkoma
 * POST + gated stub-seam already proven for server announcements.
 *
 * <h3>Ships dark</h3>
 * Gated on {@code notify.akkoma.enabled} (default false). {@link #available(String)} also
 * requires the akkoma seam to be enabled ({@code external.mastodon.enabled}) AND the
 * {@code @system} akkoma token present — so an akkoma-less / Vault-less environment
 * reports unavailable and the reconciler skips it (retried next tick). The underlying
 * notice is STUBBED until the confirmed akkoma per-user verb is wired, so a STUBBED/
 * degraded outcome is a transient FAILED→retry, never a false {@code sent}.
 */
public class AkkomaChannel implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(AkkomaChannel.class);

    public static final String NAME = "akkoma";

    private final AnnouncementMastodonClient akkoma;
    private final boolean enabled;
    private final boolean systemTokenPresent;

    public AkkomaChannel(AnnouncementMastodonClient akkoma, boolean enabled, boolean systemTokenPresent) {
        this.akkoma = akkoma;
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
        return Mono.just(enabled && akkoma.enabled() && systemTokenPresent);
    }

    @Override
    public Mono<ChannelOutcome> send(String domain, String recipientSubject, ChannelMessage message) {
        String localpart = localpartOf(recipientSubject);
        if (localpart.isBlank()) {
            return Mono.just(ChannelOutcome.SKIPPED);
        }
        String body = message.title() + "\n\n" + (message.body() == null ? "" : message.body());
        return akkoma.postLocalUserNotice(localpart, body)
                .map(AkkomaChannel::toOutcome)
                .onErrorResume(e -> {
                    log.warn("[notify-akkoma] notice to '{}' failed (retry next tick): {}",
                            localpart, e.toString());
                    return Mono.just(ChannelOutcome.FAILED);
                });
    }

    /** STUBBED (seam not wired) and degraded both become a transient FAILED → retry; only
     *  a real OK is a terminal {@code sent}. */
    private static ChannelOutcome toOutcome(AkkomaOutcome o) {
        return o.isOk() ? ChannelOutcome.SENT : ChannelOutcome.FAILED;
    }

    /** Derive the akkoma localpart from a Casdoor subject (drop org/ prefix + @domain). */
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
