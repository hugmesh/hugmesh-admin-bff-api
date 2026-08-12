package net.hugmesh.adminbff.notification.channel;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the Matrix {@code @system} channel adapter (Notifications PR5).
 */
class MatrixChannelTest {

    private static HomeserverAdminClient hs(boolean enabled) {
        WebClient any = WebClient.builder().baseUrl("http://x").build();
        return new HomeserverAdminClient(any, any, enabled);
    }

    // ── available: needs feature gate + homeserver seam + @system token ──────
    @Test
    void available_requiresEnabled_seamOn_andTokenPresent() {
        // all on → available
        assertThat(new MatrixChannel(hs(true), true, true).available("brandx").block()).isTrue();
        // feature gate off
        assertThat(new MatrixChannel(hs(true), false, true).available("brandx").block()).isFalse();
        // homeserver seam off
        assertThat(new MatrixChannel(hs(false), true, true).available("brandx").block()).isFalse();
        // @system token absent
        assertThat(new MatrixChannel(hs(true), true, false).available("brandx").block()).isFalse();
    }

    // ── send: a real OK is SENT; STUBBED/degraded is a transient FAILED ──────
    @Test
    void send_okIsSent_stubbedIsFailedRetry() {
        HomeserverAdminClient ok = mock(HomeserverAdminClient.class);
        when(ok.enabled()).thenReturn(true);
        when(ok.sendSystemDirectMessage(anyString(), any()))
                .thenReturn(Mono.just(net.hugmesh.adminbff.homeserver.HomeserverOutcome.ok()));
        MatrixChannel chOk = new MatrixChannel(ok, true, true);
        assertThat(chOk.send("brandx", "alice", new ChannelMessage("account-restriction", "T", "B")).block())
                .isEqualTo(ChannelOutcome.SENT);

        // The real HomeserverAdminClient (seam stubbed) → FAILED (retry, never false-sent).
        MatrixChannel chStub = new MatrixChannel(hs(true), true, true);
        assertThat(chStub.send("brandx", "alice", new ChannelMessage("account-restriction", "T", "B")).block())
                .isEqualTo(ChannelOutcome.FAILED);
    }

    // ── send: a blank/unresolvable localpart is a terminal SKIP ──────────────
    @Test
    void send_blankRecipient_isSkipped() {
        MatrixChannel ch = new MatrixChannel(hs(true), true, true);
        assertThat(ch.send("brandx", "  ", new ChannelMessage("c", "T", "B")).block())
                .isEqualTo(ChannelOutcome.SKIPPED);
    }

    // ── localpart derivation ─────────────────────────────────────────────────
    @Test
    void localpartOf_dropsOrgPrefixAndDomainSuffix() {
        assertThat(MatrixChannel.localpartOf("hugmesh/alice")).isEqualTo("alice");
        assertThat(MatrixChannel.localpartOf("Alice@brandx.test")).isEqualTo("alice");
        assertThat(MatrixChannel.localpartOf("org/Bob@x.y")).isEqualTo("bob");
        assertThat(MatrixChannel.localpartOf(null)).isEmpty();
    }
}
