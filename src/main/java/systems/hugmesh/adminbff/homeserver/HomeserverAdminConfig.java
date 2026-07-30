package systems.hugmesh.adminbff.homeserver;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the shared {@link HomeserverAdminClient} the access_suspension reconcile
 * loop consumes — the akkoma + tuwunel account-state admin stub-seam.
 *
 * <p>Mirrors the {@code AnnouncementConfig} / mod-bff {@code ExternalAdminConfig}
 * pattern exactly: its own {@link WebClient}s pointed at the in-cluster homeserver
 * admin endpoints, and a {@code homeserver.admin.enabled} flag (default false) so an
 * akkoma/tuwunel-less dev/test/CI run boots clean. The client is ALWAYS present (so
 * the loop can inject it non-null) but stays at the stubbed seam until enabled + the
 * confirmed admin verbs are wired in — it never hard-fails.
 *
 * <h3>Base-URL repoint behind config (DOCUMENTED)</h3>
 * <p>The account-states design repoints homeserver traffic at the per-pod mTLS
 * sidecars ({@code akkoma-proxy:4443} / {@code tuwunel-proxy:4443}) that the
 * hugmesh-generator NetworkPolicy/sidecar work introduces. Those proxies are NOT
 * necessarily present yet, so the repoint is config-driven:
 * {@code homeserver.admin.akkoma-url} / {@code homeserver.admin.tuwunel-url} default
 * to the DIRECT in-cluster service hostnames (works today, plaintext) and the
 * deployment overrides them to the {@code *-proxy:4443} mTLS services + flips
 * {@code homeserver.admin.enabled=true} once the sidecars + confirmed verbs land —
 * config-only, no code change.
 */
@Configuration(proxyBeanMethods = false)
public class HomeserverAdminConfig {

    @Bean
    HomeserverAdminClient homeserverAdminClient(
            WebClient.Builder builder,
            // Defaults: the DIRECT akkoma/tuwunel services (plaintext, works today).
            // The deployment repoints these to akkoma-proxy:4443 / tuwunel-proxy:4443
            // (mTLS sidecars) once they exist — config-only.
            @Value("${homeserver.admin.akkoma-url:http://akkoma.hugmesh-backend.svc.cluster.local:4000}")
            String akkomaUrl,
            @Value("${homeserver.admin.tuwunel-url:http://tuwunel.hugmesh-backend.svc.cluster.local:8008}")
            String tuwunelUrl,
            @Value("${homeserver.admin.enabled:false}") boolean enabled,
            // SEPARATE gate for the DOMAIN-LOCK (force-local) seams — SHIPS DARK,
            // default false so the domain-lock role lands without advertising the
            // homeserver/egress force-local effect as enforced (it stays a STUBBED
            // seam until the generator MRF image + egress policy are real).
            @Value("${homeserver.domainlock.enabled:false}") boolean domainLockEnabled,
            // The akkoma privileged admin bearer — Vault hugmesh/akkoma-admin
            // property "token" surfaced by the ESO 'akkoma-admin' ExternalSecret into a
            // K8s Secret env var, referenced here as a PLACEHOLDER (never inline). Blank
            // by default (dev/test/CI) → no Authorization header is sent.
            @Value("${homeserver.admin.akkoma-token:}") String akkomaToken) {
        return new HomeserverAdminClient(
                builder.clone().baseUrl(akkomaUrl).build(),
                builder.clone().baseUrl(tuwunelUrl).build(),
                enabled,
                domainLockEnabled,
                akkomaToken);
    }
}
