package net.hugmesh.adminbff.notification.channel;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.adminbff.notification.SystemChannelTokens;
import net.hugmesh.adminbff.announcement.AnnouncementMastodonClient;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;

import java.time.Duration;

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
            ObjectProvider<MatrixSystemDmClient> dmProvider,
            @Value("${notify.matrix.enabled:false}") boolean enabled,
            @Value("${notification.system-account.channel.matrix.token:}") String matrixToken) {
        return new MatrixChannel(homeserver, enabled, matrixToken != null && !matrixToken.isBlank(),
                dmProvider.getIfAvailable());
    }

    /**
     * The real Matrix {@code @system} DM transport. Exists ONLY when
     * {@code notify.matrix.dm.wired=true} (default false), so a deployment that has not
     * opted in keeps the stubbed admin seam and this bean (and its WebClient) is never
     * created. The base URL defaults to the same tuwunel service the admin seam dials
     * ({@code homeserver.admin.tuwunel-url}); point it at the mTLS sidecar the same way.
     */
    @Bean
    @ConditionalOnProperty(name = "notify.matrix.dm.wired", havingValue = "true")
    public MatrixSystemDmClient matrixSystemDmClient(
            WebClient.Builder builder,
            SystemChannelTokens tokens,
            @Value("${notify.matrix.base-url:${homeserver.admin.tuwunel-url:http://tuwunel.hugmesh-backend.svc.cluster.local:8008}}")
            String baseUrl,
            @Value("${notify.matrix.timeout-ms:10000}") long timeoutMs) {
        return new MatrixSystemDmClient(builder.clone().baseUrl(baseUrl).build(), tokens,
                Duration.ofMillis(timeoutMs));
    }

    /**
     * The email channel adapter. The {@link JavaMailSender} is only autoconfigured when
     * {@code spring.mail.host} is set, so it is injected via {@link ObjectProvider} and the
     * channel reports unavailable when absent — keeping a SMTP-less run clean.
     * {@code MAIL_PROVIDER} → {@code spring.mail.*} is the per-brand SMTP secret. A
     * {@link RecipientEmailResolver} bean, if one exists, resolves non-address subjects; none
     * is defined in this repo.
     */
    @Bean
    public EmailChannel emailNotificationChannel(
            ObjectProvider<JavaMailSender> mailSenderProvider,
            ObjectProvider<RecipientEmailResolver> resolverProvider,
            @Value("${notify.email.enabled:false}") boolean enabled,
            @Value("${spring.mail.host:}") String smtpHost) {
        JavaMailSender sender = mailSenderProvider.getIfAvailable();
        boolean smtpConfigured = sender != null && smtpHost != null && !smtpHost.isBlank();
        return new EmailChannel(sender, enabled, smtpConfigured, resolverProvider.getIfAvailable());
    }

    /**
     * The Akkoma (Mastodon-API) channel, reusing the existing
     * {@link AnnouncementMastodonClient} local-only POST seam (Notifications PR7).
     * {@code systemTokenPresent} reflects the {@code @system} akkoma token (Vault via ESO).
     */
    @Bean
    public AkkomaChannel akkomaNotificationChannel(
            AnnouncementMastodonClient akkoma,
            ObjectProvider<AkkomaSystemNoticeClient> noticeProvider,
            @Value("${notify.akkoma.enabled:false}") boolean enabled,
            @Value("${notification.system-account.channel.akkoma.token:}") String akkomaToken) {
        return new AkkomaChannel(akkoma, enabled, akkomaToken != null && !akkomaToken.isBlank(),
                noticeProvider.getIfAvailable());
    }

    /**
     * The real Akkoma {@code @system} notice transport. Exists ONLY when
     * {@code notify.akkoma.notice.wired=true} (default false). The base URL defaults to the
     * same akkoma service the announcement client dials ({@code external.mastodon.base-url}).
     */
    @Bean
    @ConditionalOnProperty(name = "notify.akkoma.notice.wired", havingValue = "true")
    public AkkomaSystemNoticeClient akkomaSystemNoticeClient(
            WebClient.Builder builder,
            SystemChannelTokens tokens,
            @Value("${notify.akkoma.base-url:${external.mastodon.base-url:http://akkoma.hugmesh-backend.svc.cluster.local:4000}}")
            String baseUrl,
            @Value("${notify.akkoma.timeout-ms:10000}") long timeoutMs) {
        return new AkkomaSystemNoticeClient(builder.clone().baseUrl(baseUrl).build(), tokens,
                Duration.ofMillis(timeoutMs));
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
