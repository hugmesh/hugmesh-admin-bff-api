package net.hugmesh.adminbff.argocd;

import net.hugmesh.adminbff.config.OutboundMtlsClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link ArgoCdClient} the App-Store {@code AddService} effector uses. Mirrors
 * {@code GamesReconcilerConfig} EXACTLY: ONE flag ({@code app.appstore.effector.enabled},
 * default false) gates two mutually-exclusive beans so EXACTLY ONE is registered in every
 * mode.
 *
 * <ul>
 *   <li>flag false (DEFAULT) → {@link NoopArgoCdClient}: the whole App-Store effector ships
 *       dark — the effector runs its full sequence against a no-op ArgoCD seam, so a
 *       dev/test/CI run boots clean and dials no ArgoCD;</li>
 *   <li>flag true → {@link RestArgoCdClient}: the real ArgoCD-API client (Bearer token), for
 *       the in-cluster deployment that has opted the effector in.</li>
 * </ul>
 *
 * <p>Endpoint + token come from {@code app.appstore.argocd.*} (env-driven). NO secret in
 * git — the token defaults empty and is injected by the deployment.
 *
 * <p>Transport: the real client is built on {@link OutboundMtlsClient#httpClient()} (the
 * {@code hugmesh.mtls.client.*} block, decisions 81a = A / 81b = B), so it trusts the cluster
 * CA and nothing else. ArgoCD's stock self-signed server certificate is therefore refused until
 * hugmesh-generator issues argocd-server's certificate from the cluster CA (hugmesh-admin-bff-api#62).
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OutboundMtlsClient.class)
public class ArgoCdConfig {

    /** Ships-dark default — used whenever the effector is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.appstore.effector.enabled", havingValue = "false",
            matchIfMissing = true)
    ArgoCdClient noopArgoCdClient() {
        return new NoopArgoCdClient();
    }

    /** The REAL ArgoCD-API client — wired ONLY when the effector is enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.appstore.effector.enabled", havingValue = "true")
    ArgoCdClient restArgoCdClient(
            @Value("${app.appstore.argocd.base-url:https://argocd-server.argocd.svc.cluster.local}") String baseUrl,
            @Value("${app.appstore.argocd.auth-token:}") String authToken,
            @Value("${app.appstore.argocd.project:default}") String project,
            OutboundMtlsClient mtls) {
        return new RestArgoCdClient(baseUrl, authToken, project, mtls.httpClient());
    }
}
