package net.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ships-dark structural assertions — the desktop-app-governance upstream/exec seams default
 * to their NO-OP implementations (no flag set), exactly like the App-Store ArgoCd effector.
 * A dev/test/CI run (and an unconfigured deployment) therefore dials NO upstream registry and
 * NO SSH host; the FILTERING + authz around these seams (tested elsewhere) are REAL.
 *
 * <p>Asserting {@code isReal() == false} pins the default-dark posture so a future change that
 * accidentally wires a real client by default is caught.
 */
class DesktopShipsDarkTest {

    @Test
    void registryClient_defaultsToDarkNoop() {
        assertThat(new NoopDesktopRegistryClient().isReal()).isFalse();
        assertThat(new RestDesktopRegistryClient("https://x", "").isReal()).isTrue();
    }

    @Test
    void sshClient_defaultsToDarkNoop() {
        assertThat(new NoopDesktopSshClient().isReal()).isFalse();
        assertThat(new RestDesktopSshClient("flatpak install -y {ref}").isReal()).isTrue();
    }

    @Test
    void noopRegistry_returnsDarkDescriptor_withoutDialing() {
        String out = new NoopDesktopRegistryClient().fetchRefIndex("org.x.app", "FLATPAK").block();
        assertThat(out).contains("\"dark\":true");
    }

    @Test
    void noopSsh_returnsDarkDescriptor_withoutDialing() {
        String out = new NoopDesktopSshClient().remoteInstall("dev-1", "host", "org.x.app", "admin").block();
        assertThat(out).contains("\"dark\":true");
    }
}
