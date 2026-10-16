package net.hugmesh.adminbff.notification.channel;

import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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
 *
 * <h3>Real transport (second gate)</h3>
 * When {@code notify.forum.pm.wired=true} (default false) the channel is built with a
 * {@link ForumSystemPmClient} and sends through it; availability is then
 * {@code notify.forum.enabled} AND the {@code @system} forum token ({@code seam-wired} is not
 * consulted on that path). The endpoint that client calls is a proposal that no forum-bff or
 * forum-api serves yet (see its javadoc), so until one does a reached send is a FAILED retry.
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class ForumChannel implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(ForumChannel.class);

    public static final String NAME = "forum";

    private final boolean enabled;
    private final boolean forumSeamWired;
    private final boolean systemTokenPresent;
    @Nullable
    private final ForumSystemPmClient pm;

    public ForumChannel(boolean enabled, boolean forumSeamWired, boolean systemTokenPresent) {
        this(enabled, forumSeamWired, systemTokenPresent, null);
    }

    /**
     * @param pm the real private-message transport, or null to stay on the stub
     *           ({@code notify.forum.pm.wired=false})
     */
    public ForumChannel(boolean enabled, boolean forumSeamWired, boolean systemTokenPresent,
                        @Nullable ForumSystemPmClient pm) {
        this.enabled = enabled;
        this.forumSeamWired = forumSeamWired;
        this.systemTokenPresent = systemTokenPresent;
        this.pm = pm;
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
        return Mono.just(enabled && (pm != null || forumSeamWired) && systemTokenPresent);
    }

    @Override
    public Mono<ChannelOutcome> send(String domain, String recipientSubject, ChannelMessage message) {
        if (pm != null) {
            // outcome mapping (FAILED to retry, SKIPPED for an unknown recipient) is on ForumSystemPmClient.
            return pm.sendPrivateMessage(recipientSubject, message.title(), message.body(), message.deliveryKey());
        }
        // The forum-bff send seam is not pinned (hugmesh/forum-api not yet available), so
        // a reached send is a transient FAILED (retry), NEVER a false 'sent'. Reaching here
        // requires available()==true, which forumSeamWired gates off by default.
        log.warn("[notify-forum] @system forum PM to '{}' is STUBBED — the forum-bff send "
                + "seam (hugmesh/forum-api phpBB ext) is not pinned; FAILED (retry)", recipientSubject);
        return Mono.just(ChannelOutcome.FAILED);
    }
}
