package net.hugmesh.adminbff.notification.channel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Email channel adapter for the {@code @system} sender (Notifications PR5) — the ONLY
 * net-new channel transport. Sends a neutral plain-text email FROM a sender-only
 * {@code system@<domain>} via the {@code MAIL_PROVIDER} SMTP secret.
 *
 * <h3>Sender-only system@&lt;domain&gt;</h3>
 * The {@code From} is {@code system@<domain>} (derived per outbox-row domain), matching
 * the per-domain neutral sender; the SMTP transport credentials come from
 * {@code spring.mail.*} (host/username/password), which a deployment sources from the
 * per-brand {@code MAIL_PROVIDER} secret via ESO. There is NO inbound mailbox — this is a
 * one-way notification sender.
 *
 * <h3>Ships dark + blocking-wrapped</h3>
 * Gated on {@code notify.email.enabled} (default false). {@link #available(String)} also
 * requires the SMTP host to be configured (a SMTP-less run reports unavailable → the
 * reconciler skips, never hard-fails). {@link JavaMailSender#send} is BLOCKING, so the
 * call is wrapped on {@link Schedulers#boundedElastic()} to keep the reactive reconcile
 * tick non-blocking.
 *
 * <h3>Recipient resolution</h3>
 * The recipient is resolved from the outbox {@code target} subject: a subject that is an
 * email address is used directly; anything else has no email on file and is terminally
 * {@link ChannelOutcome#SKIPPED} (a richer profile-email lookup is a PR7 follow-up).
 */
public class EmailChannel implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(EmailChannel.class);

    public static final String NAME = "email";

    private final JavaMailSender mailSender;
    private final boolean enabled;
    private final boolean smtpConfigured;

    /**
     * @param mailSender     the Spring mail sender (over the MAIL_PROVIDER SMTP secret)
     * @param enabled        the {@code notify.email.enabled} feature gate
     * @param smtpConfigured whether {@code spring.mail.host} is set (false ⇒ unavailable)
     */
    public EmailChannel(JavaMailSender mailSender, boolean enabled, boolean smtpConfigured) {
        this.mailSender = mailSender;
        this.enabled = enabled;
        this.smtpConfigured = smtpConfigured;
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
        return Mono.just(enabled && smtpConfigured && mailSender != null);
    }

    @Override
    public Mono<ChannelOutcome> send(String domain, String recipientSubject, ChannelMessage message) {
        String to = recipientEmail(recipientSubject);
        if (to == null) {
            // No email on file for this recipient — terminal skip (never retry forever).
            log.debug("[notify-email] no resolvable email for recipient '{}'; SKIPPED", recipientSubject);
            return Mono.just(ChannelOutcome.SKIPPED);
        }
        String from = "system@" + domain;
        return Mono.fromCallable(() -> {
                    SimpleMailMessage mail = new SimpleMailMessage();
                    mail.setFrom(from);
                    mail.setTo(to);
                    mail.setSubject(message.title());
                    mail.setText(message.body() == null ? message.title() : message.body());
                    mailSender.send(mail);
                    return ChannelOutcome.SENT;
                })
                // JavaMailSender.send is blocking — keep the reconcile tick non-blocking.
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(o -> log.debug("[notify-email] sent @system mail from {} to {}", from, to))
                .onErrorResume(e -> {
                    log.warn("[notify-email] send to {} failed (retry next tick): {}", to, e.toString());
                    return Mono.just(ChannelOutcome.FAILED);
                });
    }

    /** Treat an email-shaped subject as the recipient address; otherwise no email on file. */
    static String recipientEmail(String subject) {
        if (subject == null) {
            return null;
        }
        String s = subject.trim();
        // A minimal, conservative email shape — local@domain.tld with no spaces.
        if (s.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {
            return s;
        }
        return null;
    }
}
