package net.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.desktop.terminal.DeviceSshChannelFactory;
import net.hugmesh.adminbff.desktop.terminal.UnconfiguredDeviceSshChannelFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * BFF-RI: the REAL {@link RestDesktopSshClient} runs the install as a ONE-SHOT exec over the SAME
 * {@link DeviceSshChannelFactory} the terminal dials through. Buildable-now coverage:
 * <ul>
 *   <li>{@code canDial()==false} (the shipped fail-closed factory, or a null factory) → an EXPLICIT
 *       not-ready descriptor, NEVER a fake success, and NO exec attempted;</li>
 *   <li>{@code canDial()==true} → the rendered command is written to {@code exec} and the exit is
 *       reported.</li>
 * </ul>
 * The real sshj byte round-trip against a real device/QEMU is held-until-live.
 */
class RestDesktopSshClientTest {

    @Test
    void isReal_true() {
        assertThat(new RestDesktopSshClient("flatpak install -y {ref}").isReal()).isTrue();
    }

    @Test
    void nullFactory_failsClosed_dialNotReady_noFakeSuccess() {
        // a real client with NO channel factory must not pretend to install.
        RestDesktopSshClient client = new RestDesktopSshClient("flatpak install -y {ref}", null);
        String out = client.remoteInstall("dev-1", "host", "org.x.app", "admin-x").block();
        assertThat(out).contains("\"status\":\"dial-not-ready\"");
        assertThat(out).doesNotContain("\"status\":\"executed\"");
    }

    @Test
    void unconfiguredFactory_canDialFalse_failsClosed_neverExecs() {
        DeviceSshChannelFactory unconfigured = new UnconfiguredDeviceSshChannelFactory();
        assertThat(unconfigured.canDial()).isFalse();
        RestDesktopSshClient client = new RestDesktopSshClient("flatpak install -y {ref}", unconfigured);
        String out = client.remoteInstall("dev-1", "host", "org.x.app", "admin-x").block();
        assertThat(out).contains("\"status\":\"dial-not-ready\"");
    }

    @Test
    void canDialTrue_writesRenderedCommand_andReportsExit() {
        DeviceSshChannelFactory channels = mock(DeviceSshChannelFactory.class);
        when(channels.canDial()).thenReturn(true);
        when(channels.exec(eq("dev-1"), eq("host"), eq("flatpak install -y org.x.app")))
                .thenReturn(Mono.just(new DeviceSshChannelFactory.ExecResult(0, "ok")));
        RestDesktopSshClient client = new RestDesktopSshClient("flatpak install -y {ref}", channels);

        String out = client.remoteInstall("dev-1", "host", "org.x.app", "admin-x").block();
        assertThat(out).contains("\"status\":\"executed\"").contains("\"exit\":0");
        // the rendered command (ref substituted) was written to the dial exec.
        verify(channels).exec(eq("dev-1"), eq("host"), eq("flatpak install -y org.x.app"));
    }

    @Test
    void canDialTrue_hostKeyMismatch_propagatesFailClosed_notFakeSuccess() {
        DeviceSshChannelFactory channels = mock(DeviceSshChannelFactory.class);
        when(channels.canDial()).thenReturn(true);
        when(channels.exec(eq("dev-1"), eq("host"), eq("flatpak install -y org.x.app")))
                .thenReturn(Mono.error(new DeviceSshChannelFactory.HostKeyVerificationException(
                        "no pinned host_key_fp — refusing to exec")));
        RestDesktopSshClient client = new RestDesktopSshClient("flatpak install -y {ref}", channels);

        StepVerifier.create(client.remoteInstall("dev-1", "host", "org.x.app", "admin-x"))
                .expectError(DeviceSshChannelFactory.HostKeyVerificationException.class)
                .verify();
    }

    @Test
    void execDefault_failsClosed_onAFactoryThatOnlyImplementsOpen() {
        // The interface default exec MUST fail closed (no fake success) so a future canDial()=true
        // factory that forgets to override exec never silently succeeds.
        DeviceSshChannelFactory openOnly = new DeviceSshChannelFactory() {
            @Override
            public Mono<Channel> open(String d, String h, String o, int c, int r) {
                return Mono.empty();
            }
            @Override
            public boolean canDial() {
                return true;
            }
        };
        StepVerifier.create(openOnly.exec("dev-1", "host", "echo hi"))
                .expectError(IllegalStateException.class)
                .verify();
    }
}
