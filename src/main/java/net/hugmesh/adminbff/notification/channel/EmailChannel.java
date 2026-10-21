package net.hugmesh.adminbff.notification.channel;

import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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
 * email address is used directly (the resolver is not consulted). Anything else is handed to
 * the optional {@link RecipientEmailResolver}; with no resolver, or when it finds no
 * (well-formed) address, the row is terminally {@link ChannelOutcome#SKIPPED}, and when the
 * lookup itself fails it is {@link ChannelOutcome#FAILED} (retry). No resolver implementation
 * exists in this repo yet (see {@link RecipientEmailResolver}), so today only a subject that
 * is already an address is mailed.
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns these singleton collaborators and they are never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class EmailChannel implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(EmailChannel.class);

    public static final String NAME = "email";

    private final JavaMailSender mailSender;
    private final boolean enabled;
    private final boolean smtpConfigured;
    @Nullable
    private final RecipientEmailResolver resolver;

    /**
     * @param mailSender     the Spring mail sender (over the MAIL_PROVIDER SMTP secret)
     * @param enabled        the {@code notify.email.enabled} feature gate
     * @param smtpConfigured whether {@code spring.mail.host} is set (false ⇒ unavailable)
     */
    public EmailChannel(JavaMailSender mailSender, boolean enabled, boolean smtpConfigured) {
        this(mailSender, enabled, smtpConfigured, null);
    }

    /**
     * @param resolver maps a non-address subject to an address, or null to mail only subjects
     *                 that already are addresses
     */
    public EmailChannel(JavaMailSender mailSender, boolean enabled, boolean smtpConfigured,
                        @Nullable RecipientEmailResolver resolver) {
        this.mailSender = mailSender;
        this.enabled = enabled;
        this.smtpConfigured = smtpConfigured;
        this.resolver = resolver;
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
        return resolveRecipient(domain, recipientSubject)
                .flatMap(to -> deliver(domain, to, message))
                // No email on file for this recipient: terminal skip (never retry forever).
                .defaultIfEmpty(ChannelOutcome.SKIPPED)
                .onErrorResume(e -> {
                    log.warn("[notify-email] recipient lookup for '{}' failed (retry next tick): {}",
                            recipientSubject, e.toString());
                    return Mono.just(ChannelOutcome.FAILED);
                });
    }

    /** An address-shaped subject is used as is; otherwise the resolver (if any) is asked, and
     *  whatever it returns must itself be address-shaped. Empty means no address. */
    private Mono<String> resolveRecipient(String domain, String subject) {
        String direct = recipientEmail(subject);
        if (direct != null) {
            return Mono.just(direct);
        }
        if (resolver == null) {
            log.debug("[notify-email] no resolvable email for recipient '{}'; SKIPPED", subject);
            return Mono.empty();
        }
        return resolver.resolve(domain, subject)
                .mapNotNull(EmailChannel::recipientEmail);
    }

    private Mono<ChannelOutcome> deliver(String domain, String to, ChannelMessage message) {
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
