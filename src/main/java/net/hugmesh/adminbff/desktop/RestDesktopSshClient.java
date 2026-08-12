package net.hugmesh.adminbff.desktop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.desktop.terminal.DeviceSshChannelFactory;

/**
 * The REAL {@link DesktopSshClient} — runs the one-click install as a ONE-SHOT non-interactive
 * command over the SAME host-key-pinned device dial the in-UI SSH terminal uses (the
 * {@link DeviceSshChannelFactory#exec} seam), so install + terminal share ONE
 * {@code device_ssh_dial} trust path (no second TOFU surface, no separate untrusted transport).
 * Wired ONLY when {@code app.desktop.remote-install.enabled=true} ({@link DesktopRemoteInstallConfig});
 * the {@link NoopDesktopSshClient} is the ships-dark default.
 *
 * <h3>Two-key trust model (by design)</h3>
 * The BFF authenticates to the device as {@code device_ssh_dial.dial_user} using the Vault/ESO-mounted
 * dial PRIVATE key — read in-memory, {@code char[]}-wiped, never logged/persisted/returned. The
 * operator's #84-issued client key is NOT the BFF→device credential; operator accountability lives in
 * the controller/WS audit + the single-use step-up consume.
 *
 * <h3>Fail-closed when not ready</h3>
 * The real exec ADDITIONALLY requires {@code app.device-terminal.dial.enabled=true} AND an ACTIVE
 * {@code device_ssh_dial} row, i.e. {@link DeviceSshChannelFactory#canDial()}. When the wired factory
 * cannot dial (the default {@code UnconfiguredDeviceSshChannelFactory}), this reports an EXPLICIT
 * not-ready descriptor and dials NOTHING — never a silent/fake success. The held-until-live part is
 * the real byte round-trip against a reachable device.
 */
public class RestDesktopSshClient implements DesktopSshClient {

    private static final Logger log = LoggerFactory.getLogger(RestDesktopSshClient.class);

    private final String installCommandTemplate;
    private final DeviceSshChannelFactory channels;

    public RestDesktopSshClient(String installCommandTemplate) {
        this(installCommandTemplate, null);
    }

    public RestDesktopSshClient(String installCommandTemplate, DeviceSshChannelFactory channels) {
        this.installCommandTemplate = installCommandTemplate == null || installCommandTemplate.isBlank()
                ? "flatpak install -y {ref}" : installCommandTemplate;
        this.channels = channels;
    }

    @Override
    public Mono<String> remoteInstall(String deviceId, String hostname, String appRef, String operator) {
        String cmd = installCommandTemplate.replace("{ref}", appRef == null ? "" : appRef);
        // Fail-closed when the dial seam cannot dial (no real factory / no ACTIVE dial row / dial flag
        // off): report EXPLICIT not-ready, dial nothing. Never a fake success.
        if (channels == null || !channels.canDial()) {
            log.info("[desktop-remote-install] (real client) dial not ready (canDial=false) — would run "
                    + "'{}' on device={} host={} — NOT dialing (fails closed)", cmd, deviceId, hostname);
            return Mono.just("{\"deviceId\":\"" + jsonSafe(deviceId) + "\",\"appRef\":\"" + jsonSafe(appRef)
                    + "\",\"command\":\"" + jsonSafe(cmd) + "\",\"status\":\"dial-not-ready\"}");
        }
        // HELD-UNTIL-LIVE: the real one-shot exec over the pinned dial against a reachable device
        // (needs app.device-terminal.dial.enabled + an ACTIVE row + a real host).
        return channels.exec(deviceId, hostname, cmd)
                .map(r -> {
                    log.info("[desktop-remote-install] (real client) exec device={} host={} exit={}",
                            deviceId, hostname, r.exitStatus());
                    return "{\"deviceId\":\"" + jsonSafe(deviceId) + "\",\"appRef\":\"" + jsonSafe(appRef)
                            + "\",\"command\":\"" + jsonSafe(cmd) + "\",\"exit\":" + r.exitStatus()
                            + ",\"status\":\"executed\"}";
                });
    }

    @Override
    public boolean isReal() {
        return true;
    }

    private static String jsonSafe(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
