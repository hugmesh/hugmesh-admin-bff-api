package net.hugmesh.adminbff.notification;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit coverage for the {@code @system} per-channel token holder (Notifications PR3).
 * Confirms the CHANNEL-ABSENT-DEGRADE posture: with no Vault-sourced token (the empty
 * default) every channel reports its token ABSENT, so the adapter's {@code available}
 * check (PR5/PR7) skips that channel rather than attempting an unauthenticated post.
 */
class SystemChannelTokensTest {

    @Test
    void emptyDefaults_reportEveryChannelAbsent() {
        SystemChannelTokens t = new SystemChannelTokens("", "", "", "");

        assertThat(t.matrix()).isEmpty();
        assertThat(t.email()).isEmpty();
        assertThat(t.akkoma()).isEmpty();
        assertThat(t.forum()).isEmpty();
        assertThat(t.hasToken("matrix")).isFalse();
        assertThat(t.hasToken("email")).isFalse();
        assertThat(t.hasToken("akkoma")).isFalse();
        assertThat(t.hasToken("forum")).isFalse();
        assertThat(t.hasToken("unknown")).isFalse();
    }

    @Test
    void presentToken_isReportedPresent_perChannel() {
        SystemChannelTokens t = new SystemChannelTokens("mtok", "  ", "atok", null);

        assertThat(t.matrix()).contains("mtok");
        assertThat(t.hasToken("matrix")).isTrue();
        // blank-only email is treated as absent.
        assertThat(t.email()).isEmpty();
        assertThat(t.hasToken("email")).isFalse();
        assertThat(t.akkoma()).contains("atok");
        // 'mastodon' is the akkoma alias.
        assertThat(t.hasToken("mastodon")).isTrue();
        assertThat(t.forum()).isEmpty();
    }
}
