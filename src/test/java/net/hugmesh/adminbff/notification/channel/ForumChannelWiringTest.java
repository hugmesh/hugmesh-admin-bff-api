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
 * The ships-dark wiring of the phpBB transport: its bean must not exist unless
 * {@code notify.forum.pm.wired=true}, and the channel needs its own gate and token.
 */
class ForumChannelWiringTest {

    @Configuration(proxyBeanMethods = false)
    static class Collaborators {
        @Bean
        WebClient.Builder webClientBuilder() {
            return WebClient.builder();
        }

        @Bean
        HomeserverAdminClient homeserverAdminClient() {
            WebClient w = WebClient.builder().baseUrl("http://x").build();
            return new HomeserverAdminClient(w, w, false);
        }

        @Bean
        AnnouncementMastodonClient announcementMastodonClient() {
            return new AnnouncementMastodonClient(WebClient.builder().baseUrl("http://x").build(), false);
        }

        @Bean
        SystemChannelTokens systemChannelTokens(
                @org.springframework.beans.factory.annotation.Value("${notification.system-account.channel.forum.token:}") String f) {
            return new SystemChannelTokens("", "", "", f);
        }
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(Collaborators.class, ExternalChannelConfig.class);

    @Test
    void allDefaults_noTransportBean_channelDisabledAndUnavailable() {
        runner.run(ctx -> {
            assertThat(ctx).doesNotHaveBean(ForumSystemPmClient.class);
            ForumChannel ch = ctx.getBean(ForumChannel.class);
            assertThat(ch.enabled()).isFalse();
            assertThat(ch.available("brandx").block()).isFalse();
        });
    }

    @Test
    void channelEnabledWithToken_butTransportNotWired_staysUnavailableAsBefore() {
        runner.withPropertyValues("notify.forum.enabled=true",
                        "notification.system-account.channel.forum.token=t")
                .run(ctx -> {
                    assertThat(ctx).doesNotHaveBean(ForumSystemPmClient.class);
                    assertThat(ctx.getBean(ForumChannel.class).available("brandx").block()).isFalse();
                });
    }

    @Test
    void transportWiredAlone_withoutTheChannelGate_isStillDisabled() {
        runner.withPropertyValues("notify.forum.pm.wired=true",
                        "notification.system-account.channel.forum.token=t")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(ForumSystemPmClient.class);
                    assertThat(ctx.getBean(ForumChannel.class).enabled()).isFalse();
                });
    }

    @Test
    void bothGates_andToken_makeTheChannelAvailable() {
        runner.withPropertyValues("notify.forum.enabled=true", "notify.forum.pm.wired=true",
                        "notification.system-account.channel.forum.token=t")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(ForumSystemPmClient.class);
                    assertThat(ctx.getBean(ForumChannel.class).available("brandx").block()).isTrue();
                });
    }

    @Test
    void bothGates_butNoToken_isUnavailable() {
        runner.withPropertyValues("notify.forum.enabled=true", "notify.forum.pm.wired=true")
                .run(ctx -> assertThat(ctx.getBean(ForumChannel.class).available("brandx").block()).isFalse());
    }
}
