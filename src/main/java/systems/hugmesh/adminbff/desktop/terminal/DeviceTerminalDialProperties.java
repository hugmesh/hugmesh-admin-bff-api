package systems.hugmesh.adminbff.desktop.terminal;

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
 * <p>SECURITY: {@link #keyMountPath} points at the FILE the ESO-synced K8s Secret (named per device
 * by {@code device_ssh_dial.k8s_secret_name}) is mounted into. The factory reads the private dial
 * key from that mount AT DIAL TIME and NEVER logs, persists, or {@code toString}s it. The path is a
 * filesystem location only — never the key bytes — so it is safe to bind here / log on startup.
 */
@ConfigurationProperties(prefix = "app.device-terminal.dial")
public class DeviceTerminalDialProperties {

    /** The dial gate. DEFAULT false — even with the REAL transport wired
     *  ({@code app.device-terminal.enabled=true}), the dial seam stays the fail-closed
     *  {@link UnconfiguredDeviceSshChannelFactory} unless this is flipped on AND a per-device
     *  ACTIVE {@code device_ssh_dial} row exists. Flipping it on selects the host-key-pinned
     *  {@link SshjDeviceSshChannelFactory}. */
    private boolean enabled = false;

    /** Directory the per-device ESO-synced K8s Secret is mounted into. The private dial key is
     *  read from {@code <keyMountPath>/<keyFile>} at dial time. A PATH only — never key bytes —
     *  so it is safe to bind/log. The Secret is named per device by
     *  {@code device_ssh_dial.k8s_secret_name}; the deployment mounts that Secret here. */
    private String keyMountPath = "/var/run/secrets/device-ssh-dial";

    /** The file within {@link #keyMountPath} that holds the PEM/OpenSSH private dial key. */
    private String keyFile = "id_dial";

    /** The TCP port the BFF dials the mesh node's sshd on. */
    private int port = 22;

    /** Socket connect timeout for the dial. */
    private Duration connectTimeout = Duration.ofSeconds(10);

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
}
