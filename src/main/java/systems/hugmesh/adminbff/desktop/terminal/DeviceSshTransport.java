package systems.hugmesh.adminbff.desktop.terminal;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * The LIVE in-UI SSH-terminal TRANSPORT seam — the bidirectional byte channel between the
 * browser xterm.js terminal (over the {@code DeviceSshTerminalWebSocketHandler} WebSocket) and an
 * interactive shell on an authorized mesh device, riding the operator's {@code device_ssh_license}.
 *
 * <p>This is the FOUNDATION seam ONLY. It is opened <em>after</em> all connect-time gates
 * (authenticated principal + own-domain wall + active device-ssh-license re-check + step-up) have
 * passed in the handler — the transport NEVER authorizes anything itself. The default
 * implementation ({@link StubDeviceSshTransport}) DOES NOT connect to any real device: it echoes a
 * canned "ships dark" banner and closes cleanly, so with the feature flag off and only the stub
 * bean present, NO real SSH ever happens. The real SSH client implementation (sshd/Apache MINA or
 * the device-SSH channel reused from {@code DesktopSshClient}) is a LATER leg.
 *
 * <p>Mirrors {@code WorkloadClient.ExecSession} (writeStdin / resize / output / close) so the
 * xterm.js framing in the handler is byte-for-byte identical to the workload-console exec bridge.
 */
public interface DeviceSshTransport {

    /**
     * Open an interactive shell {@link Session} to {@code deviceId} sized {@code cols} x
     * {@code rows}. MUST be called only after the handler's connect-time authorization gates pass.
     *
     * @param deviceId the AUTHORIZED target device (the handler has already re-verified the
     *                 caller holds an active own-domain ssh-license for it)
     * @param hostname the device's mesh hostname/address (from the device-registry row)
     * @param operator the acting operator's Casdoor subject (the ssh-license operator key)
     * @param cols     initial terminal width
     * @param rows     initial terminal height
     */
    Mono<Session> open(String deviceId, String hostname, String operator, int cols, int rows);

    /** Whether this transport is a REAL SSH channel (true) or the ships-dark stub (false).
     *  Surfaced for a ships-dark structural assertion in tests. */
    boolean isReal();

    /** One opened interactive shell — the bidirectional byte stream + resize + close, mirroring
     *  {@code WorkloadClient.ExecSession}. */
    interface Session {

        /** Forward a chunk of terminal stdin (user keystrokes) to the remote shell. */
        void writeStdin(byte[] data);

        /** Resize the remote PTY (xterm.js {@code {"type":"resize"}} frame). */
        void resize(int cols, int rows);

        /** The remote shell's stdout/stderr bytes, streamed to the browser as WS text frames. */
        Flux<byte[]> output();

        /** Tear down the channel. Idempotent. */
        void close();
    }
}
