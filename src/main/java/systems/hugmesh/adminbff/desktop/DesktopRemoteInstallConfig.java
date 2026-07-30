package systems.hugmesh.adminbff.desktop;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import systems.hugmesh.adminbff.desktop.terminal.DeviceSshChannelFactory;

/**
 * Wires the {@link DesktopSshClient} the remote-install uses. Mirrors {@code ArgoCdConfig}
 * EXACTLY: ONE flag ({@code app.desktop.remote-install.enabled}, default false) gates two
 * mutually-exclusive beans so EXACTLY ONE is registered in every mode.
 *
 * <ul>
 *   <li>flag false (DEFAULT) → {@link NoopDesktopSshClient}: the remote-install SSH exec
 *       ships dark — the AUTHORIZATION (own-domain ssh-license for the target device) runs
 *       against a no-op exec seam, so a dev/test/CI run boots clean and dials no host;</li>
 *   <li>flag true → {@link RestDesktopSshClient}: the real SSH-exec client scaffold (the
 *       transport is a follow-on increment), for the in-cluster deployment that has opted in.</li>
 * </ul>
 *
 * <p>The install command template comes from {@code app.desktop.remote-install.command}
 * (env-driven). NO secret in git — the device-SSH key material rides the device-registry,
 * never this config.
 */
@Configuration(proxyBeanMethods = false)
public class DesktopRemoteInstallConfig {

    /** Ships-dark default — used whenever remote-install is not enabled. */
    @Bean
    @ConditionalOnProperty(name = "app.desktop.remote-install.enabled", havingValue = "false",
            matchIfMissing = true)
    DesktopSshClient noopDesktopSshClient() {
        return new NoopDesktopSshClient();
    }

    /**
     * The REAL SSH-exec client — wired ONLY when remote-install is enabled. It runs the install as a
     * one-shot command over the SAME {@link DeviceSshChannelFactory} the in-UI terminal dials through
     * (the always-present seam — the fail-closed {@link
     * systems.hugmesh.adminbff.desktop.terminal.UnconfiguredDeviceSshChannelFactory} by default,
     * the host-key-pinned sshj factory only when {@code app.device-terminal.dial.enabled=true}), so
     * install + terminal share ONE pinned device trust path. When the factory cannot dial the client
     * fails closed (no fake success).
     */
    @Bean
    @ConditionalOnProperty(name = "app.desktop.remote-install.enabled", havingValue = "true")
    DesktopSshClient restDesktopSshClient(
            @Value("${app.desktop.remote-install.command:flatpak install -y {ref}}") String command,
            DeviceSshChannelFactory channels) {
        return new RestDesktopSshClient(command, channels);
    }
}
