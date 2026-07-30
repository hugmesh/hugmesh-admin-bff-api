package systems.hugmesh.adminbff.announcement;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the announcement collaborators: the always-on {@link AnnouncementSanitizer}
 * (server-side body_html allowlist) and the SAFE GATED akkoma propagation
 * stub-seam {@link AnnouncementMastodonClient}.
 *
 * <p>The akkoma client mirrors the hugmesh-mod-bff-api
 * {@code ExternalAdminConfig} pattern exactly: its own {@link WebClient} pointed at
 * the in-cluster akkoma service (base URL grounded in the hugmesh-generator
 * akkoma manifest, overridable per env), and an {@code external.mastodon.enabled}
 * flag (default false) so an akkoma-less dev/test/CI run boots clean. The client is
 * ALWAYS present (so the service can inject it non-null) but stays at the stubbed
 * seam until enabled + a confirmed admin shape is wired in — it never hard-fails.
 */
@Configuration(proxyBeanMethods = false)
public class AnnouncementConfig {

    @Bean
    AnnouncementSanitizer announcementSanitizer() {
        return new AnnouncementSanitizer();
    }

    @Bean
    AnnouncementMastodonClient announcementMastodonClient(
            WebClient.Builder builder,
            @Value("${external.mastodon.base-url:http://akkoma.hugmesh-backend.svc.cluster.local:4000}")
            String baseUrl,
            @Value("${external.mastodon.enabled:false}") boolean enabled,
            // The akkoma privileged admin bearer — Vault hugmesh/akkoma-admin
            // property "token" via the ESO 'akkoma-admin' ExternalSecret, referenced
            // here as a PLACEHOLDER (never inline). Blank by default → no Authorization.
            @Value("${external.mastodon.admin-token:}") String adminToken) {
        return new AnnouncementMastodonClient(builder.baseUrl(baseUrl).build(), enabled, adminToken);
    }
}
