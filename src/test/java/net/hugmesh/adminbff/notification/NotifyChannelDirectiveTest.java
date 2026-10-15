package net.hugmesh.adminbff.notification;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** The pure rules of the moderator channel directive (issue #93). */
class NotifyChannelDirectiveTest {

    private static final List<String> ENABLED = List.of("matrix", "email", "akkoma", "forum");

    private static String payload(String arrayJson) {
        return "{\"target\":\"t\",\"notify_channels\":" + arrayJson + "}";
    }

    @Test
    void normalize_nullEmptyBlankAndNullElements_collapseToEmpty() {
        assertThat(NotifyChannelDirective.normalize(null)).isEmpty();
        assertThat(NotifyChannelDirective.normalize(List.of())).isEmpty();
        assertThat(NotifyChannelDirective.normalize(Arrays.asList(null, " ", ""))).isEmpty();
    }

    @Test
    void normalize_lowercasesTrimsDedupesKeepsOrder_mapsMastodonToAkkoma() {
        assertThat(NotifyChannelDirective.normalize(List.of(" Email", "MATRIX", "email", "mastodon", "akkoma")))
                .containsExactly("email", "matrix", "akkoma");
    }

    @Test
    void normalize_dropsUnknownNames() {
        assertThat(NotifyChannelDirective.normalize(List.of("sms", "forum"))).containsExactly("forum");
    }

    @Test
    void allows_noKeyOrMalformedPayload_neverNarrows() {
        for (String p : new String[] {null, "", "not json", "{}", "{\"notify_channels\":null}",
                "{\"notify_channels\":\"email\"}", "{\"notify_channels\":[]}"}) {
            assertThat(NotifyChannelDirective.allows(p, "matrix", ENABLED)).as(p).isTrue();
        }
    }

    @Test
    void allows_namedChannelOnly_whenDirectiveNamesAnEnabledChannel() {
        String p = payload("[\"email\"]");
        assertThat(NotifyChannelDirective.allows(p, "email", ENABLED)).isTrue();
        assertThat(NotifyChannelDirective.allows(p, "matrix", ENABLED)).isFalse();
    }

    @Test
    void allows_directiveNamingNoEnabledExternalChannel_doesNotNarrow() {
        assertThat(NotifyChannelDirective.allows(payload("[\"in-app\"]"), "matrix", ENABLED)).isTrue();
        assertThat(NotifyChannelDirective.allows(payload("[\"sms\"]"), "matrix", ENABLED)).isTrue();
        assertThat(NotifyChannelDirective.allows(payload("[\"email\"]"), "matrix", List.of("matrix"))).isTrue();
    }

    @Test
    void narrowedTo_ignoresNonTextualElements() {
        assertThat(NotifyChannelDirective.narrowedTo(payload("[1,null,\"email\"]"), ENABLED))
                .isEqualTo(Set.of("email"));
    }
}
