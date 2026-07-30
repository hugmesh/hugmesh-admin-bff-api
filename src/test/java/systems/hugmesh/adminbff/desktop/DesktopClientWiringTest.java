package systems.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import systems.hugmesh.adminbff.desktop.terminal.DeviceSshChannelFactory;
import systems.hugmesh.adminbff.desktop.terminal.UnconfiguredDeviceSshChannelFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the {@code @ConditionalOnProperty} dark-wiring of the desktop client seams (NOT just the
 * leaf classes): with NO {@code app.desktop.*} property set, the injected
 * {@link DesktopRegistryClient} and {@link DesktopSshClient} beans are the ships-dark Noops
 * ({@code isReal() == false}); flipping {@code app.desktop.{registry,remote-install}.enabled=true}
 * swaps in the Rest clients ({@code isReal() == true}). This guards the HIGH-fix authorization
 * paths, which assume the exec/proxy ships dark by default in dev/test/CI.
 */
class DesktopClientWiringTest {

    private final ApplicationContextRunner registry = new ApplicationContextRunner()
            .withUserConfiguration(DesktopRegistryConfig.class);

    private final ApplicationContextRunner ssh = new ApplicationContextRunner()
            .withUserConfiguration(DesktopRemoteInstallConfig.class)
            // the REAL RestDesktopSshClient now rides the device dial seam — supply the always-present
            // fail-closed factory (the same one DeviceTerminalConfig ships by default) so the
            // enabled=true wiring resolves; canDial()=false keeps it dark.
            .withBean(DeviceSshChannelFactory.class, UnconfiguredDeviceSshChannelFactory::new);

    // ── DEFAULT (no property) -> the Noop (ships dark) ───────────────────────────

    @Test
    void registryClient_defaultsToNoop_shipsDark() {
        registry.run(ctx -> {
            assertThat(ctx).hasSingleBean(DesktopRegistryClient.class);
            DesktopRegistryClient bean = ctx.getBean(DesktopRegistryClient.class);
            assertThat(bean).isInstanceOf(NoopDesktopRegistryClient.class);
            assertThat(bean.isReal()).isFalse();
        });
    }

    @Test
    void sshClient_defaultsToNoop_shipsDark() {
        ssh.run(ctx -> {
            assertThat(ctx).hasSingleBean(DesktopSshClient.class);
            DesktopSshClient bean = ctx.getBean(DesktopSshClient.class);
            assertThat(bean).isInstanceOf(NoopDesktopSshClient.class);
            assertThat(bean.isReal()).isFalse();
        });
    }

    // ── enabled=true -> the REAL Rest client ─────────────────────────────────────

    @Test
    void registryClient_whenEnabled_isRestClient() {
        registry.withPropertyValues("app.desktop.registry.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(DesktopRegistryClient.class);
            DesktopRegistryClient bean = ctx.getBean(DesktopRegistryClient.class);
            assertThat(bean).isInstanceOf(RestDesktopRegistryClient.class);
            assertThat(bean.isReal()).isTrue();
        });
    }

    @Test
    void sshClient_whenEnabled_isRestClient() {
        ssh.withPropertyValues("app.desktop.remote-install.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(DesktopSshClient.class);
            DesktopSshClient bean = ctx.getBean(DesktopSshClient.class);
            assertThat(bean).isInstanceOf(RestDesktopSshClient.class);
            assertThat(bean.isReal()).isTrue();
        });
    }
}
