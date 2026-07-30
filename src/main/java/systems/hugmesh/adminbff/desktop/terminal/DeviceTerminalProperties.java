package systems.hugmesh.adminbff.desktop.terminal;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Server-side configuration for the in-UI device SSH-terminal LIVE transport. The feature SHIPS
 * DARK: {@link #enabled} defaults to {@code false}, so the {@code DeviceSshTerminalWebSocketHandler}
 * refuses the upgrade (a clean close, NO transport opened) unless a deployment deliberately turns
 * it on AND a real {@link DeviceSshTransport} bean is present. With the flag off / only the
 * {@link StubDeviceSshTransport} bean, no real SSH ever happens.
 *
 * <p>Mirrors {@code WorkloadConsoleProperties} (a build-time, GitOps-owned gate, not a runtime/DB
 * toggle). The idle-timeout / max-session knobs are ENFORCED by the real
 * {@link SshDeviceTerminalTransport} (idle sessions are torn down; opens past the cap are rejected).
 */
@ConfigurationProperties(prefix = "app.device-terminal")
public class DeviceTerminalProperties {

    /** The generator gate. DEFAULT false — the live transport is dark unless deliberately
     *  enabled (and even then the connect-time license + step-up gates still apply, and the
     *  default transport bean is the no-dial stub). */
    private boolean enabled = false;

    /** Idle-timeout: a live session with no I/O (no stdin, no resize, no output) for longer than
     *  this is torn down by {@link SshDeviceTerminalTransport}. {@code 0}/negative disables it. */
    private Duration idleTimeout = Duration.ofMinutes(15);

    /** Max concurrent live terminal sessions per replica — {@link SshDeviceTerminalTransport}
     *  rejects an {@code open} past this cap. {@code 0}/negative disables the cap. */
    private int maxSessions = 16;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Duration getIdleTimeout() {
        return idleTimeout;
    }

    public void setIdleTimeout(Duration idleTimeout) {
        this.idleTimeout = idleTimeout;
    }

    public int getMaxSessions() {
        return maxSessions;
    }

    public void setMaxSessions(int maxSessions) {
        this.maxSessions = maxSessions;
    }
}
