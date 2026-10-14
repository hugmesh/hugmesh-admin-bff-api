package net.hugmesh.adminbff.notification.channel;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.adminbff.announcement.AnnouncementMastodonClient;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.notification.SystemChannelTokens;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The ships-dark wiring of the external channels: the real Matrix transport bean must not
 * exist unless {@code notify.matrix.dm.wired=true}, and the channel must be unavailable
 * with every flag at its default.
 */
class ExternalChannelConfigTest {

    @Configuration(proxyBeanMethods = false)
    static class Collaborators {
        @Bean
        WebClient.Builder webClientBuilder() {
            return WebClient.builder();
        }

        @Bean
        HomeserverAdminClient homeserverAdminClient() {
            WebClient w = WebClient.builder().baseUrl("http://x").build();
            return new HomeserverAdminClient(w, w, false);   // homeserver.admin.enabled=false
        }

        @Bean
        AnnouncementMastodonClient announcementMastodonClient() {
            return new AnnouncementMastodonClient(WebClient.builder().baseUrl("http://x").build(), false);
        }

        @Bean
        SystemChannelTokens systemChannelTokens(
                @org.springframework.beans.factory.annotation.Value("${notification.system-account.channel.matrix.token:}") String m,
                @org.springframework.beans.factory.annotation.Value("${notification.system-account.channel.akkoma.token:}") String a) {
            return new SystemChannelTokens(m, "", a, "");
        }
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(Collaborators.class, ExternalChannelConfig.class);

    @Test
    void allDefaults_noRealTransport_matrixChannelDisabledAndUnavailable() {
        runner.run(ctx -> {
            assertThat(ctx).doesNotHaveBean(MatrixSystemDmClient.class);
            MatrixChannel ch = ctx.getBean(MatrixChannel.class);
            assertThat(ch.enabled()).isFalse();
            assertThat(ch.available("brandx").block()).isFalse();
        });
    }

    @Test
    void channelEnabled_butTransportNotWired_staysOnTheStubbedAdminSeam() {
        runner.withPropertyValues("notify.matrix.enabled=true",
                        "notification.system-account.channel.matrix.token=t")
                .run(ctx -> {
                    assertThat(ctx).doesNotHaveBean(MatrixSystemDmClient.class);
                    // homeserver.admin.enabled=false => unavailable, exactly as before this change
                    assertThat(ctx.getBean(MatrixChannel.class).available("brandx").block()).isFalse();
                });
    }

    @Test
    void transportWiredAlone_withoutTheChannelGate_isStillDisabled() {
        runner.withPropertyValues("notify.matrix.dm.wired=true",
                        "notification.system-account.channel.matrix.token=t")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(MatrixSystemDmClient.class);
                    MatrixChannel ch = ctx.getBean(MatrixChannel.class);
                    assertThat(ch.enabled()).isFalse();   // notify.matrix.enabled still default false
                });
    }

    @Test
    void bothGates_andToken_makeTheChannelAvailable_withoutTheAdminSeam() {
        runner.withPropertyValues("notify.matrix.enabled=true", "notify.matrix.dm.wired=true",
                        "notification.system-account.channel.matrix.token=t")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(MatrixSystemDmClient.class);
                    assertThat(ctx.getBean(MatrixChannel.class).available("brandx").block()).isTrue();
                });
    }

    @Test
    void bothGates_butNoToken_isUnavailable() {
        runner.withPropertyValues("notify.matrix.enabled=true", "notify.matrix.dm.wired=true")
                .run(ctx -> assertThat(ctx.getBean(MatrixChannel.class).available("brandx").block()).isFalse());
    }

    @Test
    void akkoma_transportBeanExistsOnlyWhenWired_andAvailabilityFollowsTheGateAndToken() {
        runner.run(ctx -> assertThat(ctx).doesNotHaveBean(AkkomaSystemNoticeClient.class));
        runner.withPropertyValues("notify.akkoma.enabled=true",
                        "notification.system-account.channel.akkoma.token=t")
                .run(ctx -> {
                    assertThat(ctx).doesNotHaveBean(AkkomaSystemNoticeClient.class);
                    // external.mastodon.enabled=false and not wired: unavailable, as before
                    assertThat(ctx.getBean(AkkomaChannel.class).available("brandx").block()).isFalse();
                });
        runner.withPropertyValues("notify.akkoma.enabled=true", "notify.akkoma.notice.wired=true",
                        "notification.system-account.channel.akkoma.token=t")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(AkkomaSystemNoticeClient.class);
                    assertThat(ctx.getBean(AkkomaChannel.class).available("brandx").block()).isTrue();
                });
        runner.withPropertyValues("notify.akkoma.notice.wired=true")
                .run(ctx -> assertThat(ctx.getBean(AkkomaChannel.class).enabled()).isFalse());
    }
}
