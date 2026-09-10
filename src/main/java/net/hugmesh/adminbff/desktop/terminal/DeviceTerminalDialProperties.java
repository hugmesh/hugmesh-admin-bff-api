package net.hugmesh.adminbff.desktop.terminal;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * The SECOND, INDEPENDENT ships-dark gate for the device SSH terminal — the REAL DIAL.
 *
 * <p>{@link DeviceTerminalProperties#isEnabled() app.device-terminal.enabled} decides whether the
 * REAL session-lifecycle transport ({@link SshDeviceTerminalTransport}) is wired at all. This
 * {@code app.device-terminal.dial.*} group decides, ONE LEVEL DEEPER, whether the dial seam
 * ({@link DeviceSshChannelFactory}) is the concrete host-key-pinned sshj factory
 * ({@link SshjDeviceSshChannelFactory}) or stays the fail-closed
 * {@link UnconfiguredDeviceSshChannelFactory}. DEFAULT {@code enabled=false} so the stub/unconfigured
 * factory ships and NO real device is ever dialed.
 *
 * <p>Mirrors {@link DeviceTerminalProperties} (a build-time, GitOps-owned gate, not a runtime/DB
 * toggle). The connect-time authorization gates in {@code DeviceSshTerminalWebSocketHandler} are
 * unaffected by any of these knobs — they ALWAYS run.
 *
 * <p>SECURITY: {@link #keyMountPath} is the DIRECTORY the per-device ESO-synced K8s Secrets are
 * mounted under. Key material is PER DEVICE (operator decision, 2026-09-10, hugmesh-admin-bff-api#11):
 * the factory reads {@code <keyMountPath>/<device_ssh_dial.k8s_secret_name>/<keyFile>} AT DIAL TIME
 * and NEVER logs, persists, or {@code toString}s it. A single mesh-wide key mounted flat at
 * {@code <keyMountPath>/<keyFile>} is NOT a valid configuration and is never read — see
 * {@code SshjDeviceSshChannelFactory}. Both values are filesystem locations only — never key bytes
 * — so they are safe to bind here / log on startup.
 */
@ConfigurationProperties(prefix = "app.device-terminal.dial")
public class DeviceTerminalDialProperties {

    /** The dial gate. DEFAULT false — even with the REAL transport wired
     *  ({@code app.device-terminal.enabled=true}), the dial seam stays the fail-closed
     *  {@link UnconfiguredDeviceSshChannelFactory} unless this is flipped on AND a per-device
     *  ACTIVE {@code device_ssh_dial} row exists. Flipping it on selects the host-key-pinned
     *  {@link SshjDeviceSshChannelFactory}. */
    private boolean enabled = false;

    /** PARENT directory the per-device ESO-synced K8s Secrets are mounted under — ONE
     *  subdirectory per device, named by that device's {@code device_ssh_dial.k8s_secret_name}.
     *  The private dial key is read from {@code <keyMountPath>/<k8sSecretName>/<keyFile>} at dial
     *  time. A PATH only — never key bytes — so it is safe to bind/log. NOTE this is a PARENT of
     *  the Secret mounts, not a Secret mount itself: a key placed directly at
     *  {@code <keyMountPath>/<keyFile>} is a retired mesh-wide key and is NEVER used. */
    private String keyMountPath = "/var/run/secrets/device-ssh-dial";

    /** The file within EACH per-device Secret mount that holds the PEM/OpenSSH private dial key. */
    private String keyFile = "id_dial";

    /** The TCP port the BFF dials the mesh node's sshd on. */
    private int port = 22;

    /** Socket connect timeout for the dial. */
    private Duration connectTimeout = Duration.ofSeconds(10);

    /** HARD wall-clock deadline for a ONE-SHOT {@code exec} (the remote-install leg), covering the
     *  output capture AND the {@code join} as ONE budget, so a compromised or wedged device cannot
     *  pin a boundedElastic thread forever. It is enforced by a WATCHDOG that aborts the transport
     *  ({@code SshjDeviceSshChannelFactory.readBoundedUnderDeadline}) — NOT by a socket read
     *  timeout: sshj's reader swallows {@code SocketTimeoutException} and its channel streams park
     *  on an untimed {@code wait()}, so {@code SSHClient.setTimeout} would be inert here. See that
     *  class's javadoc for the measured detail. Deliberately NOT {@link #connectTimeout} — a real
     *  {@code flatpak install} legitimately runs far longer than a socket connect, so reusing the
     *  connect timeout here would make every remote install fail. Does NOT apply to the interactive
     *  PTY dial, whose idleness is bounded by {@code app.device-terminal.idle-timeout} instead. */
    private Duration execTimeout = Duration.ofMinutes(5);

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getKeyMountPath() {
        return keyMountPath;
    }

    public void setKeyMountPath(String keyMountPath) {
        this.keyMountPath = keyMountPath;
    }

    public String getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(Duration connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public Duration getExecTimeout() {
        return execTimeout;
    }

    public void setExecTimeout(Duration execTimeout) {
        this.execTimeout = execTimeout;
    }
}
