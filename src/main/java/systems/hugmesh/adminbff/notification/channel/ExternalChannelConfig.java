package systems.hugmesh.adminbff.notification.channel;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import systems.hugmesh.adminbff.announcement.AnnouncementMastodonClient;
import systems.hugmesh.adminbff.homeserver.HomeserverAdminClient;

/**
 * Wires the EXTERNAL {@code @system} notification channel adapters (Notifications PR5) the
 * {@code ExternalChannelReconciler} fans out to. Every channel SHIPS DARK
 * ({@code notify.<channel>.enabled} default false) so this whole subsystem lands inert and
 * a deployment opts each channel in independently.
 *
 * <p><b>Secrets via Vault/ESO, never git.</b> The {@code @system} channel credentials
 * (the Matrix token presence; the SMTP {@code spring.mail.*} host/user/password) are
 * sourced at runtime from an ExternalSecrets-materialised Secret — the property defaults
 * here are EMPTY so a Vault-less dev/test/CI run boots clean and every channel simply
 * reports itself UNAVAILABLE (the reconciler then skips it).
 */
@Configuration(proxyBeanMethods = false)
public class ExternalChannelConfig {

    /**
     * The Matrix channel adapter, reusing the existing {@link HomeserverAdminClient}
     * tuwunel seam. {@code systemTokenPresent} reflects whether the {@code @system} Matrix
     * token is configured (Vault via ESO); empty default ⇒ channel reports unavailable.
     */
    @Bean
    public MatrixChannel matrixNotificationChannel(
            HomeserverAdminClient homeserver,
            @Value("${notify.matrix.enabled:false}") boolean enabled,
            @Value("${notification.system-account.channel.matrix.token:}") String matrixToken) {
        return new MatrixChannel(homeserver, enabled, matrixToken != null && !matrixToken.isBlank());
    }

    /**
     * The email channel adapter. The {@link JavaMailSender} is only autoconfigured when
     * {@code spring.mail.host} is set, so it is injected via {@link ObjectProvider} and the
     * channel reports unavailable when absent — keeping a SMTP-less run clean.
     * {@code MAIL_PROVIDER} → {@code spring.mail.*} is the per-brand SMTP secret.
     */
    @Bean
    public EmailChannel emailNotificationChannel(
            ObjectProvider<JavaMailSender> mailSenderProvider,
            @Value("${notify.email.enabled:false}") boolean enabled,
            @Value("${spring.mail.host:}") String smtpHost) {
        JavaMailSender sender = mailSenderProvider.getIfAvailable();
        boolean smtpConfigured = sender != null && smtpHost != null && !smtpHost.isBlank();
        return new EmailChannel(sender, enabled, smtpConfigured);
    }

    /**
     * The Akkoma (Mastodon-API) channel, reusing the existing
     * {@link AnnouncementMastodonClient} local-only POST seam (Notifications PR7).
     * {@code systemTokenPresent} reflects the {@code @system} akkoma token (Vault via ESO).
     */
    @Bean
    public AkkomaChannel akkomaNotificationChannel(
            AnnouncementMastodonClient akkoma,
            @Value("${notify.akkoma.enabled:false}") boolean enabled,
            @Value("${notification.system-account.channel.akkoma.token:}") String akkomaToken) {
        return new AkkomaChannel(akkoma, enabled, akkomaToken != null && !akkomaToken.isBlank());
    }

    /**
     * The phpBB forum channel (Notifications PR7) — a visible STUBBED seam. {@code
     * notify.forum.seam-wired} defaults false until the forum-bff send seam (pinned to the
     * hugmesh/forum-api phpBB extension) is wired, so the channel is visibly unavailable
     * (the admin UI greys it) rather than a silent gap.
     */
    @Bean
    public ForumChannel forumNotificationChannel(
            @Value("${notify.forum.enabled:false}") boolean enabled,
            @Value("${notify.forum.seam-wired:false}") boolean forumSeamWired,
            @Value("${notification.system-account.channel.forum.token:}") String forumToken) {
        return new ForumChannel(enabled, forumSeamWired, forumToken != null && !forumToken.isBlank());
    }
}
