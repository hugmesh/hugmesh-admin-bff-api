package net.hugmesh.adminbff.notification.channel;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit coverage for the phpBB forum {@code @system} channel adapter (Notifications PR7) —
 * the visible STUBBED seam.
 */
class ForumChannelTest {

    @Test
    void available_isFalseUntilTheForumSeamIsWired_evenWhenEnabledWithToken() {
        // enabled + token present BUT the forum-bff seam is not wired → unavailable
        // (the admin UI greys it; it is NOT a silent gap).
        assertThat(new ForumChannel(true, false, true).available("brandx").block()).isFalse();
        // disabled
        assertThat(new ForumChannel(false, true, true).available("brandx").block()).isFalse();
        // no token
        assertThat(new ForumChannel(true, true, false).available("brandx").block()).isFalse();
        // all three on → available (the future state once the seam is pinned)
        assertThat(new ForumChannel(true, true, true).available("brandx").block()).isTrue();
    }

    @Test
    void send_whileStubbed_isFailedRetry_neverFalseSent() {
        // A reached send (while stubbed) is a transient FAILED, never a false 'sent'.
        assertThat(new ForumChannel(true, true, true)
                .send("brandx", "alice", new ChannelMessage("c", "T", "B")).block())
                .isEqualTo(ChannelOutcome.FAILED);
    }
}
