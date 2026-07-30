package systems.hugmesh.adminbff.desktop.terminal;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * The single, NARROW seam where a concrete SSH library (Apache MINA sshd / sshj) plugs into the
 * device-terminal LIVE transport. It is the ONE place that may dial a device, present operator
 * credentials, verify the device HOST KEY, and request an interactive PTY. {@link
 * SshDeviceTerminalTransport} owns the session lifecycle (idle-timeout, max-sessions, xterm framing)
 * and treats this factory as an opaque duplex byte channel — it never touches key material itself.
 *
 * <h3>How the dial credential + host-key source are RESOLVED (the formerly-FLAGGED decision)</h3>
 * The dial trust material is the {@code device_ssh_dial} registry (Liquibase band 170):
 * <ul>
 *   <li><b>Host-key source:</b> {@code device_ssh_dial.host_key_fp} pins the device's PUBLIC host
 *       key — the {@link PinnedHostKeyVerifier} compares against it on connect, so the dial is
 *       fail-closed/no-TOFU. (This is distinct from {@code device_registry.machine_key_fp}, the
 *       headscale MACHINE-key, and from {@code device_ssh_license.key_fingerprints}, the OPERATOR's
 *       client-key pins — neither is a host key.)</li>
 *   <li><b>Dial credential (TWO-KEY model):</b> the BFF authenticates as
 *       {@code device_ssh_dial.dial_user} using the BFF's OWN per-device dial PRIVATE key, synced by
 *       Vault/ESO into the K8s Secret named by {@code device_ssh_dial.k8s_secret_name} and mounted
 *       for the {@link SshjDeviceSshChannelFactory} to read AT DIAL TIME (in-memory, {@code char[]}-
 *       wiped, never logged/persisted). The operator's #84-issued client key is NOT the BFF→device
 *       credential — operator accountability lives in the WS/controller audit + the step-up consume.</li>
 * </ul>
 * The concrete sshj factory is wired only when {@code app.device-terminal.dial.enabled=true} AND an
 * ACTIVE {@code device_ssh_dial} row exists (a SUPERADMIN flips PENDING→ACTIVE via
 * {@code DesktopDialService}); otherwise the only shipped factory is
 * {@link UnconfiguredDeviceSshChannelFactory}, which fails closed (never dials), so the real
 * transport bean still ships dark even with the feature flag on. Enabling the real dial requires a
 * mandatory security re-review.
 *
 * <h3>The CONTRACT a real implementation MUST honour</h3>
 * <ol>
 *   <li><b>Verify the device host key BEFORE the channel opens.</b> Pinned / known-hosts only.
 *       TOFU-accept-any is FORBIDDEN: a host-key mismatch (or an absent pin) MUST fail the returned
 *       {@link Mono} with {@link HostKeyVerificationException}, never silently trust. This mirrors
 *       the {@code device_ssh_license} model where an un-pinned key is denied.</li>
 *   <li><b>Authenticate as the licensed operator only.</b> The handler has already re-verified the
 *       operator holds an active own-domain ssh-license for the device; the credential used here
 *       MUST be the same one that model authorizes, never a broad service key.</li>
 *   <li><b>Open an interactive PTY</b> sized {@code cols x rows} and expose it as a {@link Channel}.</li>
 * </ol>
 */
public interface DeviceSshChannelFactory {

    /**
     * Open a raw interactive PTY byte-channel to {@code hostname} as {@code operator}, sized
     * {@code cols x rows}. The implementation MUST verify the device host key (pinned/known-hosts,
     * never TOFU) before completing; a verification failure fails the {@link Mono} with
     * {@link HostKeyVerificationException}.
     *
     * @param deviceId the AUTHORIZED device id (for audit/known-hosts lookup only — authz is done)
     * @param hostname the device's mesh hostname/address (from the device-registry row)
     * @param operator the acting operator's Casdoor subject (the ssh-license operator key)
     * @param cols     initial PTY width
     * @param rows     initial PTY height
     */
    Mono<Channel> open(String deviceId, String hostname, String operator, int cols, int rows);

    /**
     * Run a ONE-SHOT, NON-INTERACTIVE command on {@code hostname} as the per-device dial user over
     * the SAME host-key-pinned dial {@link #open} uses (NO second TOFU surface) and complete with
     * an {@link ExecResult} (exit code + captured output). This is the seam the REMOTE-INSTALL leg
     * rides so install + terminal share ONE pinned {@code device_ssh_dial} trust path. The same
     * fail-closed contract applies: no ACTIVE dial row / no pinned {@code host_key_fp} / a host-key
     * mismatch MUST fail the {@link Mono} with {@link HostKeyVerificationException}, never silently
     * trust or fake a success.
     *
     * <p>The default fails closed (an {@code IllegalStateException}) so a factory that cannot dial
     * (the shipped {@link UnconfiguredDeviceSshChannelFactory}) never reports a fake success even if
     * a future caller forgets to override it.
     *
     * @param deviceId the AUTHORIZED device id (authz is already done; for audit/dial-row lookup)
     * @param hostname the device's mesh hostname/address (from the device-registry row)
     * @param command  the rendered one-shot command to run (e.g. {@code flatpak install -y <ref>})
     */
    default Mono<ExecResult> exec(String deviceId, String hostname, String command) {
        return Mono.error(new IllegalStateException(
                "device SSH channel factory cannot exec (fails closed — no real dial wired)"));
    }

    /** Whether this factory can actually dial a device (a real SSH library is wired AND the
     *  host-key source is configured). The shipped {@link UnconfiguredDeviceSshChannelFactory}
     *  returns false so the ships-dark structural assertions hold even with the flag on. */
    boolean canDial();

    /** The outcome of a one-shot {@link #exec}: the remote exit status (or {@code null} if the
     *  server sent none) and the captured merged stdout/stderr (bounded by the implementation). */
    record ExecResult(Integer exitStatus, String output) {
    }

    /**
     * One opened raw PTY channel: the duplex byte stream + resize + close. {@link
     * SshDeviceTerminalTransport} layers the session lifecycle (idle-timeout, framing) on top — a
     * {@code Channel} is intentionally dumb.
     */
    interface Channel {

        /** Forward terminal stdin (keystrokes) to the remote PTY. */
        void writeStdin(byte[] data);

        /** Resize the remote PTY. */
        void resize(int cols, int rows);

        /** The remote PTY's merged stdout/stderr bytes. Completes when the channel/shell ends. */
        Flux<byte[]> output();

        /** Tear down the channel. Idempotent. */
        void close();
    }

    /** A device host-key verification refusal — pinned/known-hosts mismatch or an absent pin.
     *  A real {@link DeviceSshChannelFactory} fails closed with this; it MUST NOT TOFU-trust. */
    class HostKeyVerificationException extends RuntimeException {
        public HostKeyVerificationException(String message) {
            super(message);
        }
    }
}
