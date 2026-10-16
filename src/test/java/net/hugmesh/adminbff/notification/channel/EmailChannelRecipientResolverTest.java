package net.hugmesh.adminbff.notification.channel;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.adminbff.announcement.AnnouncementMastodonClient;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.notification.SystemChannelTokens;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

/**
 * Recipient resolution for the email channel, against an in-memory resolver and a mock
 * {@link JavaMailSender}. No real SMTP server and no real profile lookup was exercised.
 */
class EmailChannelRecipientResolverTest {

    private final List<SimpleMailMessage> sent = new ArrayList<>();
    private final JavaMailSender sender = senderRecording();

    private JavaMailSender senderRecording() {
        JavaMailSender s = mock(JavaMailSender.class);
        doAnswer(inv -> {
            sent.add(inv.getArgument(0));
            return null;
        }).when(s).send(any(SimpleMailMessage.class));
        return s;
    }

    private ChannelOutcome send(EmailChannel ch, String subject) {
        return ch.send("brandx", subject, new ChannelMessage("c", "T", "B")).block();
    }

    @Test
    void subjectWithAnAddressOnFile_isMailedThere_fromTheRowDomain() {
        InMemoryRecipientEmailResolver r = new InMemoryRecipientEmailResolver().with("hugmesh/alice", "alice@mail.test");

        assertThat(send(new EmailChannel(sender, true, true, r), "hugmesh/alice")).isEqualTo(ChannelOutcome.SENT);
        assertThat(sent).hasSize(1);
        assertThat(sent.get(0).getTo()).containsExactly("alice@mail.test");
        assertThat(sent.get(0).getFrom()).isEqualTo("system@brandx");
        assertThat(r.lookups()).containsExactly("brandx|hugmesh/alice");
    }

    @Test
    void subjectWithNoAddressOnFile_isSkipped_andNothingIsMailed() {
        InMemoryRecipientEmailResolver r = new InMemoryRecipientEmailResolver();

        assertThat(send(new EmailChannel(sender, true, true, r), "hugmesh/ghost")).isEqualTo(ChannelOutcome.SKIPPED);
        assertThat(sent).isEmpty();
        assertThat(r.lookups()).hasSize(1);
    }

    @Test
    void failedLookup_isFailedRetry_notASkip_andNothingIsMailed() {
        InMemoryRecipientEmailResolver r = new InMemoryRecipientEmailResolver().failing();

        assertThat(send(new EmailChannel(sender, true, true, r), "hugmesh/alice")).isEqualTo(ChannelOutcome.FAILED);
        assertThat(sent).isEmpty();
    }

    @Test
    void aResolvedValueThatIsNotAnAddress_isSkipped_andNothingIsMailed() {
        InMemoryRecipientEmailResolver r = new InMemoryRecipientEmailResolver()
                .with("hugmesh/a", "not-an-address")
                .with("hugmesh/b", "a@mail.test\nBcc: evil@mail.test")
                .with("hugmesh/c", "  ");
        EmailChannel ch = new EmailChannel(sender, true, true, r);

        for (String subject : new String[] {"hugmesh/a", "hugmesh/b", "hugmesh/c"}) {
            assertThat(send(ch, subject)).as(subject).isEqualTo(ChannelOutcome.SKIPPED);
        }
        assertThat(sent).isEmpty();
    }

    @Test
    void anAddressShapedSubject_isMailedDirectly_withoutAskingTheResolver() {
        InMemoryRecipientEmailResolver r = new InMemoryRecipientEmailResolver().with("bob@mail.test", "other@mail.test");

        assertThat(send(new EmailChannel(sender, true, true, r), "bob@mail.test")).isEqualTo(ChannelOutcome.SENT);
        assertThat(sent.get(0).getTo()).containsExactly("bob@mail.test");
        assertThat(r.lookups()).isEmpty();
    }

    @Test
    void withNoResolver_aNonAddressSubjectIsStillSkipped_asBefore() {
        assertThat(send(new EmailChannel(sender, true, true), "hugmesh/alice")).isEqualTo(ChannelOutcome.SKIPPED);
        assertThat(sent).isEmpty();
    }

    // ── wiring: no resolver bean is defined here, a user-supplied one is picked up ───────
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
        SystemChannelTokens systemChannelTokens() {
            return new SystemChannelTokens("", "", "", "");
        }

        @Bean
        JavaMailSender javaMailSender() {
            return mock(JavaMailSender.class);
        }
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(Collaborators.class, ExternalChannelConfig.class)
            .withPropertyValues("notify.email.enabled=true", "spring.mail.host=smtp.test");

    @Test
    void noResolverBeanExistsByDefault_andTheChannelStillWires() {
        runner.run(ctx -> {
            assertThat(ctx).doesNotHaveBean(RecipientEmailResolver.class);
            assertThat(ctx.getBean(EmailChannel.class).available("brandx").block()).isTrue();
        });
    }

    @Test
    void aResolverBean_isUsedByTheWiredChannel() {
        runner.withBean(RecipientEmailResolver.class,
                        () -> new InMemoryRecipientEmailResolver().with("hugmesh/alice", "alice@mail.test"))
                .run(ctx -> assertThat(ctx.getBean(EmailChannel.class)
                        .send("brandx", "hugmesh/alice", new ChannelMessage("c", "T", "B")).block())
                        .isEqualTo(ChannelOutcome.SENT));
    }
}
