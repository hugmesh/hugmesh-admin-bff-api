package net.hugmesh.adminbff.desktop.terminal;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.direct.PTYMode;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyFormat;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyPairWrapper;
import net.schmizz.sshj.userauth.keyprovider.KeyProviderUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.sshterminal.DeviceSshDial;
import net.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Collections;
import java.util.Locale;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/**
 * The REAL, host-key-PINNED sshj {@link DeviceSshChannelFactory} — the concrete dial that replaces
 * the fail-closed {@link UnconfiguredDeviceSshChannelFactory} ONLY when
 * {@code app.device-terminal.dial.enabled=true} (see {@link DeviceTerminalConfig}). This is the ONE
 * place that opens a real SSH channel to a mesh node; the {@link SshDeviceTerminalTransport} layers
 * the session lifecycle on top and the {@code DeviceSshTerminalWebSocketHandler} owns ALL
 * authorization. This factory AUTHORIZES NOTHING.
 *
 * <h3>Three things this factory does, and only these</h3>
 * <ol>
 *   <li><b>Look up the ACTIVE dial row.</b> {@link DeviceSshDialRepository#findByDeviceId} for the
 *       (already-authorized) {@code deviceId}. If there is NO row, or it is not
 *       {@link DeviceSshDial#STATUS_ACTIVE ACTIVE}, REFUSE — fail the {@link Mono} with
 *       {@link HostKeyVerificationException}. No row ⇒ no dial.</li>
 *   <li><b>Pin the host key (FAIL-CLOSED, no TOFU).</b> {@link SSHClient#addHostKeyVerifier} with a
 *       {@link PinnedHostKeyVerifier} built from {@code device_ssh_dial.host_key_fp}. A mismatch (or
 *       absent pin) makes sshj abort the transport before auth — we NEVER use
 *       {@code PromiscuousVerifier} and NEVER auto-accept.</li>
 *   <li><b>Authenticate with the PER-DEVICE dial PRIVATE key.</b> Read at dial time from THIS
 *       DEVICE's own ESO-synced K8s Secret, at
 *       {@code <key-mount-path>/<device_ssh_dial.k8s_secret_name>/<key-file>}
 *       ({@link #resolveDialKeyPath}). The key bytes are loaded into sshj and NEVER logged,
 *       persisted, returned, or {@code toString}'d.</li>
 * </ol>
 *
 * <h3>Fail-closed preconditions, checked BEFORE a socket is opened</h3>
 * {@link #refusalReason} is the ONE list both {@link #open} and {@link #exec} consult, so a
 * precondition can never be enforced on one verb and forgotten on the other: the row must be ACTIVE,
 * it must carry a pinned {@code host_key_fp}, and its {@code dial_user} must NOT be {@code root} (or
 * blank). The BFF never takes a ROOT shell on a device: a control-plane pod that can become root on
 * every mesh node with an ACTIVE row is a blast radius the platform does not accept — the node-side
 * dial user is a dedicated non-root account with scoped sudo, and the row must name its OWN K8s
 * Secret ({@code k8s_secret_name}) — see below. Beyond those, that device's dial private key is
 * checked for readability BEFORE {@code connect} ({@link #preflightDialKey}) so a mis-mounted
 * deployment fails without performing a full SSH transport handshake against the device first.
 *
 * <h3>KEY MATERIAL IS PER DEVICE — a mesh-wide dial key is not a valid configuration</h3>
 * Operator decision of 2026-09-10 on hugmesh-admin-bff-api#11, answering that issue's B1
 * (<i>"per device"</i>). Until then {@code preflightDialKey}/{@code loadDialKey} both read ONE fixed
 * {@code Path.of(key-mount-path, key-file)} for every device while every doc claimed per-device
 * material: one mesh-wide BFF dial key, so a single compromise reached every node with an ACTIVE
 * row and rotating one device's credential was impossible.
 *
 * <p>Now the device's own {@code k8s_secret_name} is a REQUIRED path segment
 * ({@link #resolveDialKeyPath}), and BOTH readers resolve through that one helper with NO path
 * parameter, so no caller can inject a shared path and the two cannot drift apart.
 *
 * <p><b>What happens to a deployment that has a mesh-wide key today:</b> it FAILS CLOSED, loudly,
 * and never dials. Two moments, both message-carrying, neither of them a silent fallback:
 * <ul>
 *   <li><b>At wiring time</b>, {@link DeviceTerminalConfig} logs an ERROR naming the legacy file
 *       ({@link #meshWideKeyHint}) — so a deployment that flips the flag with the old single-Secret
 *       mount learns at startup, not on its first dial.</li>
 *   <li><b>At dial time</b>, both verbs refuse. A row with no {@code k8s_secret_name} (the shape a
 *       mesh-wide deployment has) is refused by {@link #refusalReason} before ANY dispatch; a row
 *       that names a Secret whose directory is not mounted is refused by {@link #preflightDialKey}
 *       before any socket, and the refusal SAYS a mesh-wide key was found at the mount root when
 *       one is. The old flat path is never read as a fallback.</li>
 * </ul>
 * The pod keeps serving — this gate is one feature among many on a control-plane BFF and a mount
 * mistake must not take the whole BFF down — but the dial itself is dead until per-device Secrets
 * are mounted.
 *
 * <h3>{@link #exec} is BOUNDED in MEMORY and in WALL-CLOCK TIME</h3>
 * A one-shot exec RETAINS at most {@link #MAX_EXEC_OUTPUT_BYTES} of stdout, DRAINS stderr on a
 * daemon thread, and runs the whole capture-plus-join under ONE hard deadline
 * ({@code app.device-terminal.dial.exec-timeout}) enforced by a watchdog that ABORTS the transport
 * ({@link #abortTransport}) when it expires. A compromised or wedged device can therefore neither
 * OOM this control-plane pod nor pin a boundedElastic thread indefinitely.
 *
 * <p>Two things about that are NOT obvious and were measured against the sshj 0.40.0 bytecode
 * actually on the classpath, so nobody re-derives them from the API docs:
 * <ul>
 *   <li><b>{@code SSHClient.setTimeout} does NOT bound a read.</b> It only stores a field that
 *       {@code SocketClient.onConnect} applies as {@code Socket.setSoTimeout}, and
 *       {@code net.schmizz.sshj.transport.Reader.run} CATCHES {@code SocketTimeoutException} and
 *       continues its loop unless the reader thread is interrupted — the transport does not die.
 *       Meanwhile {@code ChannelInputStream.read} parks on {@code Object.wait()} with NO timeout.
 *       So a device that completes auth, opens the session and then goes silent would park this
 *       thread forever. That is why the deadline is a WATCHDOG that closes the socket, not a
 *       socket option; {@code setTimeout} is deliberately NOT called here, because an inert knob a
 *       future reader mistakes for a control is worse than no knob.</li>
 *   <li><b>The capture keeps READING past the cap.</b> sshj replenishes the channel's local window
 *       only from {@code ChannelInputStream.read} ({@code checkWindow()} sits on the READ path), and
 *       {@code ConnectionImpl} opens with a 2 MiB window. Stopping the read at 64 KiB would stall
 *       any command whose output exceeds that window: the remote blocks writing, never exits, and
 *       the join deadline turns a previously-succeeding install into a failure. So past the cap the
 *       bytes are read and DISCARDED — memory is bounded, the window is not.</li>
 * </ul>
 *
 * <h3>Threading</h3>
 * Every sshj call (connect, auth, key read, PTY alloc, stream copy, close) is BLOCKING and is
 * therefore executed on {@link Schedulers#boundedElastic()} — never the Netty event loop. The output
 * {@link Flux} is produced by a blocking read loop {@code subscribeOn} boundedElastic; stdin/resize
 * writes are dispatched to a SINGLE {@link Scheduler.Worker} per channel so consecutive keystrokes
 * cannot be reordered across pool threads.
 *
 * <p>KNOWN, BOUNDED COST of that single worker: teardown is queued BEHIND any stdin/resize task
 * already on it (deliberately — teardown must not overtake a pending keystroke), so a
 * {@code writeStdin} blocked on an exhausted remote window DELAYS {@code session.close()} /
 * {@code ssh.disconnect()}. It is not a leak: sshj's {@code TransportImpl} sets {@code timeoutMs}
 * to 30000 and {@code Window.Remote.awaitExpansion} throws after it, which {@code writeStdinNow}
 * turns into a {@code close()}. Worst case is therefore ~30s of delayed teardown per wedged
 * channel, capped by {@code app.device-terminal.max-sessions}.
 */
public class SshjDeviceSshChannelFactory implements DeviceSshChannelFactory {

    private static final Logger log = LoggerFactory.getLogger(SshjDeviceSshChannelFactory.class);

    /** HARD cap on the output a one-shot {@link #exec} captures into memory. 64 KiB is far more
     *  than any {@code flatpak install} line emits; anything past it is discarded with a marker
     *  rather than grown without limit on a control-plane pod. */
    static final int MAX_EXEC_OUTPUT_BYTES = 64 * 1024;

    /** The dial user the BFF must NEVER authenticate as (see the class javadoc). */
    private static final String ROOT_DIAL_USER = "root";

    /** The ONLY host-key fingerprint algorithm a live dial accepts (see {@link #refusalReason}). */
    private static final String SHA256_PIN_LABEL = "SHA256";

    /** A K8s Secret name is a DNS-1123 SUBDOMAIN. {@code device_ssh_dial.k8s_secret_name} becomes a
     *  PATH SEGMENT under the dial key mount, so it is matched against the real Kubernetes rule
     *  rather than merely scanned for {@code ".."} — this admits nothing that is not a legal Secret
     *  name, and therefore no separator, no traversal, no whitespace, no empty segment. */
    private static final Pattern SECRET_NAME =
            Pattern.compile("[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*");

    /** The Kubernetes limit on a Secret name (DNS-1123 subdomain), mirrored by the {@code @Size} on
     *  the image-build ingest DTO that seeds the column. */
    private static final int MAX_SECRET_NAME_LENGTH = 253;

    private final DeviceSshDialRepository dials;
    private final DeviceTerminalDialProperties props;
    private final Scheduler ioScheduler;

    public SshjDeviceSshChannelFactory(DeviceSshDialRepository dials,
                                       DeviceTerminalDialProperties props) {
        this(dials, props, Schedulers.boundedElastic());
    }

    SshjDeviceSshChannelFactory(DeviceSshDialRepository dials, DeviceTerminalDialProperties props,
                                Scheduler ioScheduler) {
        this.dials = dials;
        this.props = props;
        this.ioScheduler = ioScheduler;
    }

    @Override
    public Mono<Channel> open(String deviceId, String hostname, String operator, int cols, int rows) {
        // 1) ACTIVE dial row gate. No ACTIVE row -> REFUSE (do NOT dial, do NOT TOFU).
        return dials.findByDeviceId(deviceId)
                .switchIfEmpty(Mono.error(new HostKeyVerificationException(
                        "no device_ssh_dial row for device=" + deviceId + " — refusing to dial")))
                // Verify ACTIVE + pinned host-key + non-root dial user before the blocking dial.
                .flatMap(dial -> dialIfPermitted(dial, deviceId, hostname, cols, rows));
    }

    @Override
    public Mono<ExecResult> exec(String deviceId, String hostname, String command) {
        // SAME fail-closed ACTIVE-dial-row + pinned-host-key gate as open() — install rides the SAME
        // pinned device_ssh_dial trust path as the terminal (no second TOFU surface).
        return dials.findByDeviceId(deviceId)
                .switchIfEmpty(Mono.error(new HostKeyVerificationException(
                        "no device_ssh_dial row for device=" + deviceId + " — refusing to exec")))
                // Verify ACTIVE + pinned host-key + non-root dial user before the blocking exec.
                .flatMap(dial -> execIfPermitted(dial, deviceId, hostname, command));
    }

    /**
     * The fail-closed dial preconditions, shared by {@link #open} and {@link #exec} so a rule can
     * never be enforced on one verb and forgotten on the other. Returns the refusal reason, or
     * {@code null} when the row may be dialed.
     */
    private static String refusalReason(DeviceSshDial dial, String deviceId, String verb) {
        if (!dial.isActive()) {
            return "device_ssh_dial for device=" + deviceId + " is status=" + dial.status()
                    + " (not ACTIVE) — refusing to " + verb;
        }
        if (dial.hostKeyFp() == null || dial.hostKeyFp().isBlank()) {
            return "device_ssh_dial for device=" + deviceId
                    + " has no pinned host_key_fp — refusing to " + verb + " (no TOFU)";
        }
        if (!SHA256_PIN_LABEL.equals(PinnedHostKeyVerifier.labelOf(dial.hostKeyFp()))) {
            // The MD5-pin rule, enforced on BOTH sides. DesktopDialService.activate refuses to make
            // a non-SHA256: pin ACTIVE, but that is a rule about the ACTIVATION path only: any row
            // that reaches ACTIVE another way (a backfill, a restored dump, a future direct-to-ACTIVE
            // seed) would otherwise dial on a 128-bit digest with practical collision attacks. This
            // is the same both-sides treatment the root rule already gets, for the same reason.
            return "device_ssh_dial for device=" + deviceId + " has a non-SHA256: host_key_fp"
                    + " — refusing to " + verb + " (an MD5 pin may not reach a live dial)";
        }
        if (isRootOrBlank(dial.dialUser())) {
            return "device_ssh_dial for device=" + deviceId + " has dial_user='" + dial.dialUser()
                    + "' — refusing to " + verb + " as root (the BFF never takes a root shell)";
        }
        String keyIdentity = dialKeyIdentityRefusal(dial);
        if (keyIdentity != null) {
            // PER-DEVICE KEY MATERIAL (operator decision, 2026-09-10): the row must name its OWN
            // K8s Secret. Checked HERE, in the one shared list, so both verbs refuse a row with no
            // per-device key BEFORE any dispatch — and checked again in resolveDialKeyPath, which
            // is the only thing that can produce a key path at all.
            return "device_ssh_dial for device=" + deviceId + " " + keyIdentity
                    + " — refusing to " + verb;
        }
        return null;
    }

    /** True for {@code root} in any casing/padding, and for an absent/blank dial user (fail-closed:
     *  an unnamed dial user is an unreviewed one). */
    static boolean isRootOrBlank(String dialUser) {
        if (dialUser == null || dialUser.isBlank()) {
            return true;
        }
        return ROOT_DIAL_USER.equals(dialUser.trim().toLowerCase(Locale.ROOT));
    }

    /** Gate the dial on the shared preconditions then dispatch the blocking dial on ioScheduler. */
    private Mono<Channel> dialIfPermitted(DeviceSshDial dial, String deviceId, String hostname,
                                          int cols, int rows) {
        String refusal = refusalReason(dial, deviceId, "dial");
        if (refusal != null) {
            return Mono.error(new HostKeyVerificationException(refusal));
        }
        return Mono.fromCallable(() -> dial(deviceId, hostname, dial, cols, rows))
                .subscribeOn(ioScheduler);
    }

    /** Gate the exec on the shared preconditions then dispatch the blocking exec on ioScheduler. */
    private Mono<ExecResult> execIfPermitted(DeviceSshDial dial, String deviceId,
                                             String hostname, String command) {
        String refusal = refusalReason(dial, deviceId, "exec");
        if (refusal != null) {
            return Mono.error(new HostKeyVerificationException(refusal));
        }
        return Mono.fromCallable(() -> execBlocking(deviceId, hostname, dial, command))
                .subscribeOn(ioScheduler);
    }

    /** Blocking: connect + pin-verify host key + auth + run ONE non-interactive command, capturing
     *  a BOUNDED amount of output under a HARD deadline. Runs on {@link #ioScheduler}. */
    private ExecResult execBlocking(String deviceId, String hostname, DeviceSshDial dial, String command)
            throws IOException {
        // Key readability BEFORE the socket: a mis-mounted Secret must not cost a full handshake.
        preflightDialKey(dial);
        long deadlineMs = execDeadlineMillis();
        var ssh = new SSHClient();
        ssh.addHostKeyVerifier(new PinnedHostKeyVerifier(deviceId, dial.hostKeyFp()));
        ssh.setConnectTimeout((int) props.getConnectTimeout().toMillis());
        // NOTE: ssh.setTimeout() is deliberately NOT called — it is INERT as a read bound here.
        // See the class javadoc: sshj's Reader swallows SocketTimeoutException and ChannelInputStream
        // parks on an untimed wait(). captureBounded's watchdog is the real deadline.
        try {
            ssh.connect(hostname, props.getPort());
            KeyProvider keys = loadDialKey(ssh, dial);
            ssh.authPublickey(dial.dialUser(), keys);
            Session session = ssh.startSession();
            Session.Command cmd = session.exec(command);
            return captureBounded(ssh, cmd, deviceId, hostname, props.getPort(), dial, deadlineMs);
        } finally {
            closeQuietly(ssh);
        }
    }

    /** The one-shot exec deadline: {@code app.device-terminal.dial.exec-timeout}. Deliberately NOT
     *  the (10s) connect timeout — a real {@code flatpak install} legitimately outlives a socket
     *  connect, so reusing it would make every remote install fail. Floored at 1ms. */
    private long execDeadlineMillis() {
        return Math.max(1L, props.getExecTimeout().toMillis());
    }

    /**
     * BOUNDED capture of a one-shot command: at most {@link #MAX_EXEC_OUTPUT_BYTES} of stdout
     * RETAINED in memory, stderr drained on a daemon thread, and the WHOLE thing (capture + join)
     * under ONE hard wall-clock deadline enforced by a watchdog that aborts the transport. See the
     * class javadoc for why the deadline cannot be a socket option and why the read continues past
     * the memory cap.
     */
    private static ExecResult captureBounded(SSHClient ssh, Session.Command cmd, String deviceId,
                                             String hostname, int port, DeviceSshDial dial,
                                             long deadlineMs)
            throws IOException {
        Thread stderrDrain = new Thread(() -> discardQuietly(cmd.getErrorStream()),
                "device-exec-stderr-" + deviceId);
        stderrDrain.setDaemon(true);
        stderrDrain.start();
        long startNanos = System.nanoTime();
        String output;
        Integer exit;
        try {
            output = readBoundedUnderDeadline(cmd.getInputStream(), MAX_EXEC_OUTPUT_BYTES,
                    deadlineMs, () -> abortTransport(ssh));
            // ONE budget for the whole exec: whatever the capture already spent is not spent again.
            long spentMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
            cmd.join(Math.max(1L, deadlineMs - spentMs), TimeUnit.MILLISECONDS);
            exit = cmd.getExitStatus();
        } catch (ConnectionException e) {
            throw new IOException("one-shot exec failed or exceeded its " + deadlineMs
                    + "ms deadline for device=" + deviceId + " — aborting (bounded exec)", e);
        } finally {
            stderrDrain.interrupt();
        }
        log.info("[desktop-remote-install] (sshj) one-shot exec device={} host={}:{} dialUser={} "
                + "exit={} chars={} (host-key PINNED, bounded)", deviceId, hostname, port,
                dial.dialUser(), exit, output.length());
        return new ExecResult(exit, output);
    }

    /**
     * {@link #readBounded} under a HARD wall-clock deadline. A watchdog thread runs {@code abort}
     * when the deadline expires; for the real dial that CLOSES THE SOCKET, which makes sshj's
     * transport die and notify every channel of the error, which in turn wakes the untimed
     * {@code ChannelInputStream.read} this thread is parked in so it throws instead of waiting
     * forever. The reader thread is ALSO interrupted, because that read honours an interrupt
     * ({@code InterruptedIOException}) — two independent ways out of the same park.
     *
     * <p>The abort and the "we finished" flag are exchanged under one lock so a watchdog that fires
     * at the same instant the read completes cannot leave a stray interrupt on a boundedElastic
     * thread that is about to be handed back to the pool.
     *
     * @param abort what to do when the deadline expires; MUST NOT block (a socket close does not)
     */
    static String readBoundedUnderDeadline(InputStream in, int max, long deadlineMs, Runnable abort)
            throws IOException {
        Thread reader = Thread.currentThread();
        Object lock = new Object();
        AtomicBoolean finished = new AtomicBoolean(false);
        AtomicBoolean expired = new AtomicBoolean(false);
        Thread watchdog = new Thread(
                () -> awaitDeadlineThenAbort(deadlineMs, lock, finished, expired, abort, reader),
                "device-exec-deadline");
        watchdog.setDaemon(true);
        watchdog.start();
        try {
            return readBounded(in, max);
        } catch (IOException e) {
            if (expired.get()) {
                throw new IOException("one-shot exec exceeded its " + deadlineMs
                        + "ms deadline while reading output — transport aborted (bounded exec)", e);
            }
            throw e;
        } finally {
            synchronized (lock) {
                finished.set(true);
            }
            watchdog.interrupt();
            // Clear an interrupt the watchdog may have set on us before handing this
            // boundedElastic thread back to the pool.
            Thread.interrupted();
        }
    }

    /**
     * The deadline watchdog's body: sleep out the deadline, then — unless the read has already
     * finished — abort the transport and interrupt the reader, BOTH under {@code lock} so a
     * watchdog firing at the instant the read completes cannot leave a stray interrupt behind.
     */
    private static void awaitDeadlineThenAbort(long deadlineMs, Object lock, AtomicBoolean finished,
                                               AtomicBoolean expired, Runnable abort, Thread reader) {
        try {
            Thread.sleep(deadlineMs);
        } catch (InterruptedException e) {
            return; // the read finished first and cancelled us
        }
        synchronized (lock) {
            if (finished.get()) {
                return;
            }
            expired.set(true);
            abort.run();
            reader.interrupt();
        }
    }

    /**
     * Read to EOF RETAINING at most {@code max} bytes as UTF-8, appending an explicit marker when
     * the remote had more to say.
     *
     * <p>Reading PAST the cap (and discarding) is deliberate and load-bearing, not laziness: sshj
     * replenishes the channel's local window only from {@code ChannelInputStream.read}, so a reader
     * that STOPS at the cap stalls any remote whose output exceeds the initial 2 MiB window — the
     * command then never exits and the join deadline turns a working install into a failure. Memory
     * is what is bounded here; WALL-CLOCK time is bounded by {@link #readBoundedUnderDeadline}.
     */
    static String readBounded(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int kept = 0;
        boolean truncated = false;
        int n = in.read(buf);
        while (n != -1) {
            if (kept < max) {
                int keep = Math.min(n, max - kept);
                out.write(buf, 0, keep);
                kept += keep;
                truncated = truncated || keep < n;
            } else {
                truncated = true;
            }
            n = in.read(buf);
        }
        String text = out.toString(StandardCharsets.UTF_8);
        return truncated ? text + "\n…[output truncated at " + max + " bytes]" : text;
    }

    /**
     * Abort the SSH transport NOW, without the graceful close handshake: close the underlying
     * socket directly. {@code SSHClient.disconnect()} writes a DISCONNECT packet first and
     * {@code AbstractChannel.close()} waits for a close confirmation (up to sshj's 30s
     * {@code timeoutMs}) — neither is usable from a deadline watchdog whose whole job is to not
     * wait. Closing the socket makes sshj's Reader fail, which calls {@code TransportImpl.die},
     * which notifies every channel of the error and wakes any parked read. Best-effort, never
     * throws.
     */
    static void abortTransport(SSHClient ssh) {
        try {
            java.net.Socket socket = ssh.getSocket();
            if (socket != null) {
                socket.close();
            }
        } catch (Exception ignore) { //NOPMD EmptyCatchBlock - best-effort abort, already failing
        }
    }

    /** Drain-and-discard a stream until EOF/close; best-effort, never throws. */
    private static void discardQuietly(InputStream in) {
        byte[] buf = new byte[8192];
        try {
            while (in.read(buf) != -1) {
                continue; // discarded on purpose — stderr is drained only to keep the window open
            }
        } catch (IOException ignore) { //NOPMD EmptyCatchBlock - best-effort drain, channel closing
        }
    }

    @Override
    public boolean canDial() {
        return true;
    }

    /** Blocking: connect + pin-verify host key + auth with the per-device dial key + alloc PTY +
     *  start shell. Runs on {@link #ioScheduler}. */
    private Channel dial(String deviceId, String hostname, DeviceSshDial dial, int cols, int rows)
            throws IOException {
        // Key readability BEFORE the socket: a mis-mounted Secret must not cost a full handshake.
        preflightDialKey(dial);
        var ssh = new SSHClient();
        // FAIL-CLOSED host-key pin — the ONLY verifier. No known-hosts, no PromiscuousVerifier.
        ssh.addHostKeyVerifier(new PinnedHostKeyVerifier(deviceId, dial.hostKeyFp()));
        ssh.setConnectTimeout((int) props.getConnectTimeout().toMillis());
        try {
            ssh.connect(hostname, props.getPort());
            // Per-device dial PRIVATE key from the ESO-synced mount. Loaded into sshj and never
            // logged/persisted/returned. loadDialKey reads the mounted file's bytes only here.
            KeyProvider keys = loadDialKey(ssh, dial);
            ssh.authPublickey(dial.dialUser(), keys);

            Session session = ssh.startSession();
            session.allocatePTY("xterm", Math.max(1, cols), Math.max(1, rows), 0, 0,
                    Collections.<PTYMode, Integer>emptyMap());
            Session.Shell shell = session.startShell();
            log.info("[device-terminal] (sshj) PTY open device={} host={}:{} dialUser={} {}x{} "
                    + "(host-key PINNED)", deviceId, hostname, props.getPort(), dial.dialUser(),
                    cols, rows);
            return new SshjChannel(ssh, session, shell, ioScheduler, deviceId);
        } catch (Throwable t) {
            // Best-effort teardown on any failure (incl. host-key refusal) so no socket leaks.
            closeQuietly(ssh);
            throw t;
        }
    }

    /**
     * Resolve the ONE key file this device's dial may use:
     * {@code <key-mount-path>/<device_ssh_dial.k8s_secret_name>/<key-file>}.
     *
     * <p>This is the WHOLE of the "per-device key material" decision (operator, 2026-09-10, on
     * hugmesh-admin-bff-api#11: <i>"per device"</i>). Before it, both
     * {@link #preflightDialKey} and {@link #loadDialKey} read one fixed
     * {@code Path.of(keyMountPath, keyFile)} for EVERY device — one mesh-wide BFF dial key, so a
     * single compromise reached every node with an ACTIVE row and rotating one device's credential
     * was impossible. The device's own {@code k8s_secret_name} is now a REQUIRED path segment, so
     * a mesh-wide key is not merely discouraged: there is no code path that can reach one.
     *
     * <p>Both callers resolve THROUGH HERE and neither accepts a path from its caller, so the two
     * cannot drift apart and no caller can inject a mount-root path.
     *
     * @throws IOException (fail-closed) when the row carries no usable {@code k8s_secret_name}, or
     *     when the resolved path would escape the mount root.
     */
    static Path resolveDialKeyPath(DeviceTerminalDialProperties props, DeviceSshDial dial)
            throws IOException {
        String refusal = dialKeyIdentityRefusal(dial);
        if (refusal != null) {
            throw new IOException("device_ssh_dial for device=" + dial.deviceId() + " " + refusal
                    + " — refusing to resolve a dial key");
        }
        Path mountRoot = Path.of(props.getKeyMountPath()).normalize();
        Path keyPath = mountRoot.resolve(dial.k8sSecretName()).resolve(props.getKeyFile())
                .normalize();
        // Belt-and-braces, INDEPENDENT of the name syntax rule above: whatever the row or the
        // key-file setting says, the resolved file must still live under the configured mount.
        if (!keyPath.startsWith(mountRoot)) {
            throw new IOException("resolved dial key path escapes the mount for device="
                    + dial.deviceId() + " (k8sSecret=" + dial.k8sSecretName() + ") — refusing");
        }
        return keyPath;
    }

    /**
     * The per-device KEY-IDENTITY precondition, shared by {@link #refusalReason} (so BOTH verbs
     * refuse before any dispatch) and by {@link #resolveDialKeyPath} (so the path helper itself can
     * never produce a mount-root path). Returns the refusal reason, or {@code null} when the row
     * names usable per-device key material.
     *
     * <p>A row with NO {@code k8s_secret_name} is exactly the shape a mesh-wide-key deployment has;
     * it is refused rather than silently falling back to a shared key.
     *
     * <p>Returns a REASON PHRASE ("names no k8s_secret_name (...)"), not a whole sentence, so each
     * caller can name its own subject and verb — and so the three call sites cannot disagree about
     * the rule while wording it differently. {@code public} only because
     * {@code DesktopDialService.policyRefusal} (another package) applies the SAME predicate on the
     * activation path, the way the MD5-pin and never-root rules are already applied on both sides.
     */
    public static String dialKeyIdentityRefusal(DeviceSshDial dial) {
        String secret = dial.k8sSecretName();
        if (secret == null || secret.isBlank()) {
            return "names no k8s_secret_name (per-device dial key material is REQUIRED; a single"
                    + " mesh-wide dial key is no longer a valid configuration)";
        }
        if (secret.length() > MAX_SECRET_NAME_LENGTH || !SECRET_NAME.matcher(secret).matches()) {
            // A Secret NAME is not a secret, so it is safe to echo — and an operator debugging a
            // bad ingest needs to see the value that was rejected.
            return "has a malformed k8s_secret_name='" + secret + "' (must be ONE DNS-1123 Secret"
                    + " name; it is used as a path segment under the dial key mount)";
        }
        return null;
    }

    /**
     * PRE-CONNECT check that THIS DEVICE's ESO-synced dial key is actually mounted and readable, so
     * a mis-mounted deployment fails BEFORE a socket is opened and a full SSH transport handshake
     * (host-key verification included) is performed against the device. The bytes are NOT read here
     * — {@link #loadDialKey} does that, and re-resolves the same path from the same helper.
     *
     * <p>When the key is missing AND a legacy mesh-wide key is sitting at the mount ROOT, the
     * refusal SAYS SO: that is the deployment shape the per-device decision retired, and an
     * operator who only sees "not present" while a key file is plainly there would look in the
     * wrong place.
     */
    private void preflightDialKey(DeviceSshDial dial) throws IOException {
        Path keyPath = resolveDialKeyPath(props, dial);
        if (!Files.isReadable(keyPath)) {
            // Path/provenance only — never the (absent) bytes. k8s_secret_name is the mount hint.
            throw new IOException("per-device dial private key not present at mount for device="
                    + dial.deviceId() + " (k8sSecret=" + dial.k8sSecretName() + ", expected "
                    + keyPath + ")" + meshWideKeyHint(props));
        }
    }

    /**
     * The " — a MESH-WIDE dial key is mounted at ..." clause, or {@code ""} when the mount root
     * holds no legacy flat key. Also used at wiring time ({@link DeviceTerminalConfig}) so a
     * deployment that still mounts one mesh-wide key is told at STARTUP, not at 3am on the first
     * dial. Returns a PATH, never bytes.
     */
    static String meshWideKeyHint(DeviceTerminalDialProperties props) {
        Path legacy = Path.of(props.getKeyMountPath(), props.getKeyFile());
        if (!Files.isReadable(legacy)) {
            return "";
        }
        return " — a MESH-WIDE dial key is mounted at " + legacy + "; mesh-wide dial keys are NO"
                + " LONGER a valid configuration: mount ONE Secret per device at "
                + Path.of(props.getKeyMountPath(), "<k8s_secret_name>", props.getKeyFile());
    }

    /**
     * Read THIS DEVICE's dial PRIVATE key from its own ESO-synced K8s Secret mount and hand it to
     * sshj as a {@link KeyProvider}, parsed ENTIRELY IN MEMORY (never re-read from / written to disk
     * after this single read). The key text is held only in a transient {@code char[]} that is wiped
     * in a {@code finally}. NOTHING here logs, returns, or persists the key bytes.
     *
     * <p>It takes NO path argument on purpose: it resolves the device's own key through
     * {@link #resolveDialKeyPath}, so there is no seam through which a mesh-wide path could be
     * handed in, and a regression in {@link #preflightDialKey} alone cannot make this read a shared
     * key.
     *
     * <p>The parse is FORCED here rather than left to sshj, because sshj's {@code FileKeyProvider}
     * is lazy and this method wipes the buffer it would have read from — see the inline comment.
     */
    // Package-private, not private, ONLY so SshjDeviceSshChannelFactoryTest can pin that THIS
    // reader (not just preflightDialKey) resolves the device's own key: a live dial cannot be
    // reached in a unit test, so without a direct call a regression here would go unmeasured.
    KeyProvider loadDialKey(SSHClient ssh, DeviceSshDial dial)
            throws IOException {
        Path keyPath = resolveDialKeyPath(props, dial);
        byte[] raw = Files.readAllBytes(keyPath);
        char[] pem = new String(raw, StandardCharsets.UTF_8).toCharArray();
        java.util.Arrays.fill(raw, (byte) 0);
        try {
            // Detect the key format from the in-memory text, pick the matching sshj FileKeyProvider
            // factory from this client's config, and init it from a Reader over the same text — so
            // the key is parsed without a second disk read. Each Reader is a CharArrayReader wrapping
            // the SAME wiped-in-finally char[] (no copy), so no intermediate unencrypted String of
            // the key is allocated onto the heap to outlive this call until GC.
            KeyFormat format = KeyProviderUtil.detectKeyFileFormat(
                    new java.io.CharArrayReader(pem), false);
            FileKeyProvider provider = null;
            for (Factory.Named<FileKeyProvider> f
                    : ssh.getTransport().getConfig().getFileKeyProviderFactories()) {
                if (f.getName().equals(format.toString())) {
                    provider = f.create();
                    break;
                }
            }
            if (provider == null) {
                // Fail closed: an unsupported/unknown dial key format must NOT silently fall back.
                throw new IOException("unsupported dial private key format (" + format
                        + ") for device=" + dial.deviceId());
            }
            // No PasswordFinder: the dial key is an unencrypted, build-seeded ops key. An encrypted
            // key would fail to parse here (fail-closed) rather than prompt. A fresh CharArrayReader
            // re-reads the same char[] from the start (detect's reader was a separate instance).
            provider.init(new java.io.CharArrayReader(pem));
            // FORCE THE PARSE HERE, while the chars are still alive. sshj's FileKeyProvider is LAZY:
            // init() only stores the Reader, and BaseFileKeyProvider.readKeyPair() does not run until
            // something asks for a key — which, on the dial path, is ssh.authPublickey() AFTER this
            // method has returned and the finally below has zeroed the buffer. Returning the raw
            // provider therefore handed sshj a reader over a char[] of NULs and public-key auth could
            // never succeed ("Supported PEM Key Type not found for header [header not found]").
            // Measured against sshj 0.40.0 on this classpath, not inferred; pinned by
            // SshjDeviceSshChannelFactoryTest.loadDialKey_*.
            KeyPair parsed = new KeyPair(provider.getPublic(), provider.getPrivate());
            // The returned provider holds the PARSED key objects only — no Reader, no char[].
            return new KeyPairWrapper(parsed);
        } finally {
            java.util.Arrays.fill(pem, '\0'); // wipe transient key chars
        }
    }

    /** Best-effort close. Catches Exception, not just IOException: the deadline watchdog may have
     *  already closed the socket underneath us, and {@code Socket.isConnected()} still reports true
     *  for a CLOSED socket, so the graceful disconnect below can fail in more ways than one. */
    private static void closeQuietly(SSHClient ssh) {
        try {
            if (ssh.isConnected()) {
                ssh.disconnect();
            }
        } catch (Exception ignore) { //NOPMD EmptyCatchBlock - best-effort close, already failing
        }
    }

    /**
     * A raw duplex PTY channel over the sshj shell. ALL I/O is blocking and is confined to
     * {@link #scheduler} (boundedElastic). {@link #output()} is a blocking read loop; {@link
     * #writeStdin}/{@link #resize}/{@link #close} are dispatched to ONE {@link Scheduler.Worker}
     * created for this channel, so consecutive stdin/resize tasks are SERIALISED — scheduling each
     * on the pool directly let two keystrokes land on different workers and arrive out of order,
     * which on a live PTY changes the command executed. NO key material is held here — only the
     * live shell streams.
     */
    static final class SshjChannel implements Channel {

        private final SSHClient ssh;
        private final Session session;
        private final Session.Shell shell;
        private final OutputStream stdin;
        private final InputStream stdout;
        private final Scheduler scheduler;
        private final Scheduler.Worker worker;
        private final String deviceId;
        private final AtomicBoolean closed = new AtomicBoolean(false);

        SshjChannel(SSHClient ssh, Session session, Session.Shell shell, Scheduler scheduler,
                    String deviceId) {
            this.ssh = ssh;
            this.session = session;
            this.shell = shell;
            this.stdin = shell.getOutputStream();
            this.stdout = shell.getInputStream();
            this.scheduler = scheduler;
            // ONE worker for the lifetime of the channel: a Worker executes its tasks in submission
            // order, which scheduler.schedule() across a pool does NOT guarantee.
            this.worker = scheduler.createWorker();
            this.deviceId = deviceId;
        }

        @Override
        public void writeStdin(byte[] data) {
            scheduleUnlessClosed(() -> writeStdinNow(data));
        }

        private void writeStdinNow(byte[] data) {
            try {
                stdin.write(data);
                stdin.flush();
            } catch (IOException e) {
                close();
            }
        }

        @Override
        public void resize(int cols, int rows) {
            scheduleUnlessClosed(() -> resizeNow(cols, rows));
        }

        private void resizeNow(int cols, int rows) {
            try {
                shell.changeWindowDimensions(Math.max(1, cols), Math.max(1, rows), 0, 0);
            } catch (IOException e) {
                // a resize failure should not kill the session by itself
                log.debug("[device-terminal] (sshj) resize failed device={}", deviceId);
            }
        }

        /** Queue an ordered task, unless the channel is already tearing down. */
        private void scheduleUnlessClosed(Runnable task) {
            if (closed.get()) {
                return;
            }
            submit(task);
        }

        /** Queue on the channel's single worker; a disposed worker rejects, which just means the
         *  teardown already ran. */
        private void submit(Runnable task) {
            try {
                worker.schedule(task);
            } catch (RejectedExecutionException ignore) { //NOPMD EmptyCatchBlock - already closed
            }
        }

        @Override
        public Flux<byte[]> output() {
            // Read stdout bytes in a blocking loop, emitting chunks until EOF or close. This runs on
            // the POOL, not the worker: a blocking read loop would otherwise occupy the single
            // worker thread and starve every stdin write.
            return Flux.<byte[]>create(this::drainOutputToSink).subscribeOn(scheduler);
        }

        /** Blocking stdout reader: emit chunks until EOF, close on error or completion. */
        private void drainOutputToSink(reactor.core.publisher.FluxSink<byte[]> sink) {
            byte[] buf = new byte[8192];
            try {
                int n;
                while (!closed.get() && (n = stdout.read(buf)) != -1) {
                    byte[] chunk = new byte[n];
                    System.arraycopy(buf, 0, chunk, 0, n);
                    sink.next(chunk);
                }
                sink.complete();
            } catch (IOException e) {
                if (closed.get()) {
                    sink.complete();
                } else {
                    sink.error(e);
                }
            } finally {
                close();
            }
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                // Teardown is queued behind whatever stdin/resize work is already on the worker, so
                // it can never overtake it (submit bypasses the closed guard on purpose).
                submit(this::tearDownChannel);
            }
        }

        /** Close the SSH session and disconnect the client; best-effort, never throws. */
        private void tearDownChannel() {
            try {
                session.close();
            } catch (Exception ignore) { //NOPMD EmptyCatchBlock - best-effort teardown
            }
            try {
                ssh.disconnect();
            } catch (IOException ignore) { //NOPMD EmptyCatchBlock - best-effort teardown
            }
            worker.dispose();
            log.info("[device-terminal] (sshj) channel closed device={}", deviceId);
        }
    }
}
