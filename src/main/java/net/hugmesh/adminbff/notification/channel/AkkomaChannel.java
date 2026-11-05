package net.hugmesh.adminbff.notification.channel;

import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.announcement.AkkomaOutcome;
import net.hugmesh.adminbff.announcement.AnnouncementMastodonClient;

/**
 * Akkoma (Mastodon-API) channel adapter for the {@code @system} sender (Notifications
 * PR7). Posts a neutral notice to the recipient as a {@code direct} status from the
 * {@code @system} account, via the EXISTING {@link AnnouncementMastodonClient} akkoma client
 * ({@link AnnouncementMastodonClient#postLocalUserNotice}) — reusing its WebClient and its
 * {@code external.mastodon.enabled} gate.
 *
 * <h3>Ships dark</h3>
 * Gated on {@code notify.akkoma.enabled} (default false). {@link #available(String)} also
 * requires the akkoma seam to be enabled ({@code external.mastodon.enabled}) AND the
 * {@code @system} akkoma token present — so an akkoma-less / Vault-less environment
 * reports unavailable and the reconciler skips it (retried next tick). On this path the
 * notice is a Mastodon-API {@code direct} status posted by
 * {@link AnnouncementMastodonClient#postLocalUserNotice} with the {@code @system} token;
 * only its OK is {@code sent}, and a STUBBED (seam gate or token absent) or degraded
 * outcome is a transient FAILED→retry, never a false {@code sent}. This path has no
 * account-existence probe, so it can report {@code sent} for a recipient with no Akkoma
 * account; the second gate below does probe.
 *
 * <h3>Real transport (second gate)</h3>
 * When {@code notify.akkoma.notice.wired=true} (default false) the channel is built with an
 * {@link AkkomaSystemNoticeClient} and posts a {@code direct} status as the {@code @system}
 * account through that client (lookup probe + {@code Idempotency-Key}) instead of the
 * announcement client's notice seam. That path does not need
 * {@code external.mastodon.enabled} (that gate guards the ADMIN bearer, which a notice never
 * uses); availability is then {@code notify.akkoma.enabled} AND the {@code @system} token.
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class AkkomaChannel implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(AkkomaChannel.class);

    public static final String NAME = "akkoma";

    private final AnnouncementMastodonClient akkoma;
    private final boolean enabled;
    private final boolean systemTokenPresent;
    @Nullable
    private final AkkomaSystemNoticeClient notice;

    public AkkomaChannel(AnnouncementMastodonClient akkoma, boolean enabled, boolean systemTokenPresent) {
        this(akkoma, enabled, systemTokenPresent, null);
    }

    /**
     * @param notice the probing Mastodon-API transport, or null to post through the
     *               announcement client's notice seam ({@code notify.akkoma.notice.wired=false})
     */
    public AkkomaChannel(AnnouncementMastodonClient akkoma, boolean enabled, boolean systemTokenPresent,
                         @Nullable AkkomaSystemNoticeClient notice) {
        this.akkoma = akkoma;
        this.enabled = enabled;
        this.systemTokenPresent = systemTokenPresent;
        this.notice = notice;
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
        return Mono.just(enabled && (notice != null || akkoma.enabled()) && systemTokenPresent);
    }

    @Override
    public Mono<ChannelOutcome> send(String domain, String recipientSubject, ChannelMessage message) {
        String localpart = localpartOf(recipientSubject);
        if (localpart.isBlank()) {
            return Mono.just(ChannelOutcome.SKIPPED);
        }
        String body = message.title() + "\n\n" + (message.body() == null ? "" : message.body());
        if (notice != null) {
            // outcome mapping (FAILED to retry, SKIPPED for a missing account) is on AkkomaSystemNoticeClient.
            return notice.sendDirectNotice(localpart, body, message.deliveryKey());
        }
        return akkoma.postLocalUserNotice(localpart, body)
                .map(AkkomaChannel::toOutcome)
                .onErrorResume(e -> {
                    log.warn("[notify-akkoma] notice to '{}' failed (retry next tick): {}",
                            localpart, e.toString());
                    return Mono.just(ChannelOutcome.FAILED);
                });
    }

    /** STUBBED (seam gate or token absent) and degraded both become a transient FAILED →
     *  retry; only a real OK is a terminal {@code sent}. */
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
