package systems.hugmesh.adminbff.desktop;

import reactor.core.publisher.Mono;

/**
 * The seam to the device-SSH channel the REMOTE-INSTALL rides — the admin's existing
 * per-device SSH license ([[hugmesh-device-license-registry]]) is the transport; this
 * runs the one-click install command (or, later, bridges an interactive TTY) over it. NO
 * new daemon.
 *
 * <p>SHIPS DARK by default: the {@link NoopDesktopSshClient} logs the would-be SSH exec and
 * returns a placeholder WITHOUT dialing any host, so the AUTHORIZATION around it (the admin
 * must hold an ACTIVE ssh-license for the own-domain target device) is fully exercisable —
 * and a ships-dark test can assert {@code isReal() == false} — without a live mesh. Wired by
 * {@link DesktopRemoteInstallConfig}: ONE flag ({@code app.desktop.remote-install.enabled},
 * default false) selects Noop vs real.
 */
public interface DesktopSshClient {

    /**
     * Run the one-click install of {@code appRef} on {@code device} over the admin's
     * device-SSH license. The caller has ALREADY proven the admin holds an ACTIVE
     * ssh-license for this own-domain device — this only executes. Returns a short result
     * descriptor.
     */
    Mono<String> remoteInstall(String deviceId, String hostname, String appRef, String operator);

    /** Whether this is the REAL SSH exec client (true) or the ships-dark Noop (false). */
    boolean isReal();
}
