package systems.hugmesh.adminbff.notification.channel;

import org.junit.jupiter.api.Test;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Unit coverage for the email {@code @system} channel adapter (Notifications PR5) — the
 * only net-new channel transport. Uses a mock {@link JavaMailSender} (no real SMTP).
 */
class EmailChannelTest {

    // ── available: feature gate + SMTP configured + sender present ───────────
    @Test
    void available_requiresEnabled_smtpConfigured_andSender() {
        JavaMailSender sender = mock(JavaMailSender.class);
        assertThat(new EmailChannel(sender, true, true).available("brandx").block()).isTrue();
        assertThat(new EmailChannel(sender, false, true).available("brandx").block()).isFalse();
        assertThat(new EmailChannel(sender, true, false).available("brandx").block()).isFalse();
        // CHANNEL-ABSENT-DEGRADE: a SMTP-less run (null sender) reports unavailable.
        assertThat(new EmailChannel(null, true, false).available("brandx").block()).isFalse();
    }

    // ── send: a sender-only system@<domain> From + the recipient address ─────
    @Test
    void send_setsSenderOnlySystemFrom_andRecipient() {
        AtomicReference<SimpleMailMessage> sent = new AtomicReference<>();
        JavaMailSender sender = mock(JavaMailSender.class);
        doAnswer(inv -> {
            sent.set(inv.getArgument(0));
            return null;
        }).when(sender).send(any(SimpleMailMessage.class));
        EmailChannel ch = new EmailChannel(sender, true, true);

        ChannelOutcome outcome = ch.send("brandx", "alice@brandx.test",
                new ChannelMessage("account-restriction", "Your account access changed", "neutral body")).block();

        assertThat(outcome).isEqualTo(ChannelOutcome.SENT);
        SimpleMailMessage m = sent.get();
        assertThat(m.getFrom()).isEqualTo("system@brandx");      // sender-only system@<domain>
        assertThat(m.getTo()).containsExactly("alice@brandx.test");
        assertThat(m.getSubject()).isEqualTo("Your account access changed");
        assertThat(m.getText()).isEqualTo("neutral body");
    }

    // ── send: no email on file for the recipient → terminal SKIP, no send ────
    @Test
    void send_nonEmailRecipient_isSkipped_andNeverSends() {
        JavaMailSender sender = mock(JavaMailSender.class);
        EmailChannel ch = new EmailChannel(sender, true, true);

        ChannelOutcome outcome = ch.send("brandx", "hugmesh/alice",
                new ChannelMessage("c", "T", "B")).block();

        assertThat(outcome).isEqualTo(ChannelOutcome.SKIPPED);
        verify(sender, never()).send(any(SimpleMailMessage.class));
    }

    // ── send: SMTP transport failure → FAILED (retry next tick), never throws ─
    @Test
    void send_transportFailure_isFailed_neverThrows() {
        JavaMailSender sender = mock(JavaMailSender.class);
        doThrow(new MailSendException("smtp down")).when(sender).send(any(SimpleMailMessage.class));
        EmailChannel ch = new EmailChannel(sender, true, true);

        ChannelOutcome outcome = ch.send("brandx", "alice@brandx.test",
                new ChannelMessage("c", "T", "B")).block();

        assertThat(outcome).isEqualTo(ChannelOutcome.FAILED);
    }

    @Test
    void recipientEmail_acceptsEmailShape_rejectsOthers() {
        assertThat(EmailChannel.recipientEmail("alice@brandx.test")).isEqualTo("alice@brandx.test");
        assertThat(EmailChannel.recipientEmail("hugmesh/alice")).isNull();
        assertThat(EmailChannel.recipientEmail("alice")).isNull();
        assertThat(EmailChannel.recipientEmail(null)).isNull();
    }
}
