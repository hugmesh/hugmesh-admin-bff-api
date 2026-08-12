package net.hugmesh.adminbff.forum;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the {@link PhpbbAdminClient} the {@link ForumAdminController} consumes — the
 * admin-bff → forum-bff forum-console stub-seam.
 *
 * <p>Mirrors {@code AnnouncementConfig} / {@code HomeserverAdminConfig} /
 * {@code FederationUsernameConfig} / mod-bff {@code ExternalAdminConfig} EXACTLY: its
 * own {@link WebClient} pointed at the in-cluster forum-bff service, and an
 * {@code external.forum.enabled} flag (default false) so a forum-bff-less
 * dev/test/CI run boots clean. The client is ALWAYS present (so the controller can
 * inject it non-null) but stays at the STUBBED seam until enabled + the forum-bff
 * {@code /bff/forum/admin/**} contract + the hugmesh {@code forum-api} phpBB
 * extension shape are pinned — it never hard-fails.
 *
 * <h3>Base-URL repoint behind config (mTLS sidecar — DOCUMENTED)</h3>
 * <p>{@code external.forum.base-url} defaults to the DIRECT in-cluster forum-bff
 * service ({@code http://hugmesh-forum-bff-api.hugmesh-backend.svc.cluster.local:8080},
 * works today, plaintext). The deployment repoints it to the forum-bff mTLS service
 * (presenting the {@code hugmesh-forum-bff-api-mtls} client cert the generator/PKI
 * work provisions) and flips {@code external.forum.enabled=true} once the
 * {@code /bff/forum/admin/**} contract + the phpBB extension land — config-only, no
 * code change. The whole leg is gated {@code hasRole('ADMIN')} end-to-end so an admin
 * without ROLE_FORUM is not blocked by the user floor.
 */
@Configuration(proxyBeanMethods = false)
public class ForumAdminConfig {

    @Bean
    PhpbbAdminClient phpbbAdminClient(
            WebClient.Builder builder,
            // Default: the DIRECT forum-bff service (plaintext, works today). The
            // deployment repoints this to the forum-bff mTLS service once it exists —
            // config-only. forum-bff owns the single phpBB client; admin-bff calls it.
            @Value("${external.forum.base-url:http://hugmesh-forum-bff-api.hugmesh-backend.svc.cluster.local:8080}")
            String baseUrl,
            @Value("${external.forum.enabled:false}") boolean enabled) {
        // PhpbbAdminClient builds path segments PRE-ENCODED (enc() on user/post ids), so the
        // WebClient must NOT re-encode (EncodingMode.NONE) — otherwise a '%2F' becomes
        // '%252F' (double-encoding). The id-bearing paths are the only encoded inputs and
        // are already percent-encoded by enc(); every other path segment is a static literal.
        org.springframework.web.util.DefaultUriBuilderFactory uriFactory =
                new org.springframework.web.util.DefaultUriBuilderFactory(baseUrl);
        uriFactory.setEncodingMode(org.springframework.web.util.DefaultUriBuilderFactory.EncodingMode.NONE);
        WebClient http = builder.clone().uriBuilderFactory(uriFactory).baseUrl(baseUrl).build();
        return new PhpbbAdminClient(http, enabled);
    }
}
