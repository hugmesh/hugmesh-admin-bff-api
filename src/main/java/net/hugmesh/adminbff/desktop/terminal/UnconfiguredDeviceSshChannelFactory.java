package net.hugmesh.adminbff.desktop.terminal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The shipped {@link DeviceSshChannelFactory}: it FAILS CLOSED and never dials a device, because
 * the prerequisites for a real dial are an UNRESOLVED design decision (see {@link
 * DeviceSshChannelFactory} — the BFF has no device host-key/known-hosts source, and no operator
 * private key reaches it). This is the safety net that keeps {@link SshDeviceTerminalTransport}
 * shipping dark even when {@code app.device-terminal.enabled=true}: the real session lifecycle
 * (idle-timeout, max-sessions, framing) is fully exercised, but the actual SSH channel never opens,
 * so NO real device is reached and the build stays green offline.
 *
 * <p>A concrete MINA-sshd / sshj factory (with pinned host-key verification) is the follow-on that
 * the FLAGGED host-key-storage decision unblocks. Until then, {@link #open} errors with a clear,
 * non-distinguishing reason so a flag-on deployment fails safe rather than silently TOFU-trusting.
 */
public class UnconfiguredDeviceSshChannelFactory implements DeviceSshChannelFactory {

    private static final Logger log = LoggerFactory.getLogger(UnconfiguredDeviceSshChannelFactory.class);

    static final String UNCONFIGURED_REASON =
            "device-terminal SSH channel factory is not configured (no SSH client / no device "
            + "host-key source) — refusing to dial rather than TOFU-trust; this is the FLAGGED "
            + "follow-on decision";

    @Override
    public Mono<Channel> open(String deviceId, String hostname, String operator, int cols, int rows) {
        // FAIL CLOSED — no dial, no TOFU. The transport turns this into a generic, audited close.
        log.warn("[device-terminal] channel factory UNCONFIGURED — refusing to dial device={} host={} "
                + "operator={} ({})", deviceId, hostname, operator, UNCONFIGURED_REASON);
        return Mono.error(new IllegalStateException(UNCONFIGURED_REASON));
    }

    @Override
    public boolean canDial() {
        return false;
    }
}
