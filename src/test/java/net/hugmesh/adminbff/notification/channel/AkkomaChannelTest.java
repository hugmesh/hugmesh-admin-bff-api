package net.hugmesh.adminbff.notification.channel;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.announcement.AkkomaOutcome;
import net.hugmesh.adminbff.announcement.AnnouncementMastodonClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Unit coverage for the Akkoma {@code @system} channel adapter (Notifications PR7). */
class AkkomaChannelTest {

    private static AnnouncementMastodonClient akkoma(boolean enabled) {
        return new AnnouncementMastodonClient(WebClient.builder().baseUrl("http://x").build(), enabled);
    }

    @Test
    void available_requiresEnabled_seamOn_andTokenPresent() {
        assertThat(new AkkomaChannel(akkoma(true), true, true).available("brandx").block()).isTrue();
        assertThat(new AkkomaChannel(akkoma(true), false, true).available("brandx").block()).isFalse();
        assertThat(new AkkomaChannel(akkoma(false), true, true).available("brandx").block()).isFalse();
        assertThat(new AkkomaChannel(akkoma(true), true, false).available("brandx").block()).isFalse();
    }

    @Test
    void send_okIsSent_stubbedIsFailedRetry() {
        AnnouncementMastodonClient ok = mock(AnnouncementMastodonClient.class);
        when(ok.enabled()).thenReturn(true);
        when(ok.postLocalUserNotice(anyString(), any())).thenReturn(Mono.just(AkkomaOutcome.ok()));
        assertThat(new AkkomaChannel(ok, true, true)
                .send("brandx", "alice", new ChannelMessage("c", "T", "B")).block())
                .isEqualTo(ChannelOutcome.SENT);

        // Real client (seam stubbed) → FAILED (retry), never a false sent.
        assertThat(new AkkomaChannel(akkoma(true), true, true)
                .send("brandx", "alice", new ChannelMessage("c", "T", "B")).block())
                .isEqualTo(ChannelOutcome.FAILED);
    }

    @Test
    void send_blankRecipient_isSkipped() {
        assertThat(new AkkomaChannel(akkoma(true), true, true)
                .send("brandx", " ", new ChannelMessage("c", "T", "B")).block())
                .isEqualTo(ChannelOutcome.SKIPPED);
    }

    @Test
    void localpartOf_dropsOrgPrefixAndDomainSuffix() {
        assertThat(AkkomaChannel.localpartOf("hugmesh/alice")).isEqualTo("alice");
        assertThat(AkkomaChannel.localpartOf("Bob@x.y")).isEqualTo("bob");
    }
}
