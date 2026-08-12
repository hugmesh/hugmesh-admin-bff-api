package net.hugmesh.adminbff.notification.channel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * phpBB forum channel adapter for the {@code @system} sender (Notifications PR7) —
 * deliberately a STUBBED SEAM, not a silent gap.
 *
 * <h3>Why stubbed, and why that is honest</h3>
 * Posting a forum private message as {@code @system} needs the forum-bff seam, which is
 * itself pinned to the {@code hugmesh/forum-api} phpBB extension — NOT yet available. So
 * this channel is wired as a first-class {@link NotificationChannel} (so the subsystem +
 * the admin UI can SEE it and GREY it out — a visible "forum notifications: not yet
 * available" rather than a silently-missing option), but its {@link #available(String)}
 * returns false until the forum-bff send seam is wired AND its enable flag is on. The
 * reconciler therefore SKIPS it cleanly (records nothing, retries) instead of pretending a
 * delivery. {@link #send} likewise resolves to {@link ChannelOutcome#FAILED} (transient,
 * retry) if ever reached while stubbed — never a false {@code sent}.
 *
 * <p>Ships dark on {@code notify.forum.enabled} (default false). {@code forumSeamWired}
 * (default false) is the second gate the real forum-bff client flips when pinned.
 */
public class ForumChannel implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(ForumChannel.class);

    public static final String NAME = "forum";

    private final boolean enabled;
    private final boolean forumSeamWired;
    private final boolean systemTokenPresent;

    public ForumChannel(boolean enabled, boolean forumSeamWired, boolean systemTokenPresent) {
        this.enabled = enabled;
        this.forumSeamWired = forumSeamWired;
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
        // Available ONLY once the forum-bff seam is pinned/wired AND the token is present.
        // Today forumSeamWired defaults false → the channel is visibly unavailable (UI
        // greys it), never a silent gap.
        return Mono.just(enabled && forumSeamWired && systemTokenPresent);
    }

    @Override
    public Mono<ChannelOutcome> send(String domain, String recipientSubject, ChannelMessage message) {
        // The forum-bff send seam is not pinned (hugmesh/forum-api not yet available), so
        // a reached send is a transient FAILED (retry), NEVER a false 'sent'. Reaching here
        // requires available()==true, which forumSeamWired gates off by default.
        log.warn("[notify-forum] @system forum PM to '{}' is STUBBED — the forum-bff send "
                + "seam (hugmesh/forum-api phpBB ext) is not pinned; FAILED (retry)", recipientSubject);
        return Mono.just(ChannelOutcome.FAILED);
    }
}
