package net.hugmesh.adminbff.desktop;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the {@link DesktopRegistryClient} the desktop Discover registry endpoint uses to
 * fetch upstream Flatpak/OCI indices. Mirrors {@code ArgoCdConfig} EXACTLY: ONE flag
 * ({@code app.desktop.registry.enabled}, default false) gates two mutually-exclusive beans
 * so EXACTLY ONE is registered in every mode.
 *
 * <ul>
 *   <li>flag false (DEFAULT) → {@link NoopDesktopRegistryClient}: the upstream proxy ships
 *       dark — the registry endpoint's FILTERING + authz run against a no-op upstream seam,
 *       so a dev/test/CI run boots clean and dials no registry;</li>
 *   <li>flag true → {@link RestDesktopRegistryClient}: the real upstream-proxy client
 *       (Bearer token), for the in-cluster deployment that has opted the proxy in.</li>
 * </ul>
 *
 * <p>Endpoint + token come from {@code app.desktop.registry.*} (env-driven). NO secret in
 * git — the token defaults empty and is injected by the deployment.
 */
@Configuration(proxyBeanMethods = false)
public class DesktopRegistryConfig {

    /** Ships-dark default — used whenever the upstream proxy is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.desktop.registry.enabled", havingValue = "false",
            matchIfMissing = true)
    DesktopRegistryClient noopDesktopRegistryClient() {
        return new NoopDesktopRegistryClient();
    }

    /** The REAL upstream-proxy client — wired ONLY when the proxy is enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.desktop.registry.enabled", havingValue = "true")
    DesktopRegistryClient restDesktopRegistryClient(
            @Value("${app.desktop.registry.base-url:https://flathub-oci.example.invalid}") String baseUrl,
            @Value("${app.desktop.registry.auth-token:}") String authToken) {
        return new RestDesktopRegistryClient(baseUrl, authToken);
    }
}
