package net.hugmesh.adminbff.desktop.terminal;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.direct.PTYMode;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyFormat;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;
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
import java.util.Collections;
import java.util.Locale;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

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
 *   <li><b>Authenticate with the per-device dial PRIVATE key.</b> Read at dial time from the
 *       ESO-synced K8s Secret mounted at {@code app.device-terminal.dial.key-mount-path}; the Secret
 *       is named per device by {@code device_ssh_dial.k8s_secret_name}. The key bytes are loaded
 *       into sshj and NEVER logged, persisted, returned, or {@code toString}'d.</li>
 * </ol>
 *
 * <h3>Fail-closed preconditions, checked BEFORE a socket is opened</h3>
 * {@link #refusalReason} is the ONE list both {@link #open} and {@link #exec} consult, so a
 * precondition can never be enforced on one verb and forgotten on the other: the row must be ACTIVE,
 * it must carry a pinned {@code host_key_fp}, and its {@code dial_user} must NOT be {@code root} (or
 * blank). The BFF never takes a ROOT shell on a device: a control-plane pod that can become root on
 * every mesh node with an ACTIVE row is a blast radius the platform does not accept — the node-side
 * dial user is a dedicated non-root account with scoped sudo. Beyond those, the dial private key is
 * checked for readability BEFORE {@code connect} ({@link #preflightDialKey}) so a mis-mounted
 * deployment fails without performing a full SSH transport handshake against the device first.
 *
 * <h3>{@link #exec} is BOUNDED</h3>
 * A one-shot exec captures at most {@link #MAX_EXEC_OUTPUT_BYTES}, joins the remote command under
 * {@code app.device-terminal.dial.exec-timeout} rather than waiting forever, sets that same deadline
 * as the socket read timeout, and DRAINS stderr on a daemon thread (an undrained channel window
 * stalls the remote, which would otherwise keep stdout from ever reaching EOF). A compromised or
 * wedged device can therefore neither OOM this control-plane pod nor pin an I/O thread indefinitely.
 *
 * <h3>Threading</h3>
 * Every sshj call (connect, auth, key read, PTY alloc, stream copy, close) is BLOCKING and is
 * therefore executed on {@link Schedulers#boundedElastic()} — never the Netty event loop. The output
 * {@link Flux} is produced by a blocking read loop {@code subscribeOn} boundedElastic; stdin/resize
 * writes are dispatched to a SINGLE {@link Scheduler.Worker} per channel so consecutive keystrokes
 * cannot be reordered across pool threads.
 */
public class SshjDeviceSshChannelFactory implements DeviceSshChannelFactory {

    private static final Logger log = LoggerFactory.getLogger(SshjDeviceSshChannelFactory.class);

    /** HARD cap on the output a one-shot {@link #exec} captures into memory. 64 KiB is far more
     *  than any {@code flatpak install} line emits; anything past it is discarded with a marker
     *  rather than grown without limit on a control-plane pod. */
    static final int MAX_EXEC_OUTPUT_BYTES = 64 * 1024;

    /** The dial user the BFF must NEVER authenticate as (see the class javadoc). */
    private static final String ROOT_DIAL_USER = "root";

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
        if (isRootOrBlank(dial.dialUser())) {
            return "device_ssh_dial for device=" + deviceId + " has dial_user='" + dial.dialUser()
                    + "' — refusing to " + verb + " as root (the BFF never takes a root shell)";
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
        Path keyPath = preflightDialKey(dial);
        long deadlineMs = execDeadlineMillis();
        var ssh = new SSHClient();
        ssh.addHostKeyVerifier(new PinnedHostKeyVerifier(deviceId, dial.hostKeyFp()));
        ssh.setConnectTimeout((int) props.getConnectTimeout().toMillis());
        // Socket read timeout: a device that opens the channel and then goes silent cannot pin this
        // thread past the exec deadline. NOT set on the interactive dial() path — an idle PTY is
        // legitimate there and is torn down by the transport's own idle-timeout instead.
        ssh.setTimeout((int) Math.min(Integer.MAX_VALUE, deadlineMs));
        try {
            ssh.connect(hostname, props.getPort());
            KeyProvider keys = loadDialKey(ssh, dial, keyPath);
            ssh.authPublickey(dial.dialUser(), keys);
            Session session = ssh.startSession();
            Session.Command cmd = session.exec(command);
            return captureBounded(cmd, deviceId, hostname, props.getPort(), dial, deadlineMs);
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
     * BOUNDED capture of a one-shot command: at most {@link #MAX_EXEC_OUTPUT_BYTES} of stdout held
     * in memory, stderr drained on a daemon thread so an undrained channel window cannot stall the
     * remote, and a HARD {@code join} deadline so a command that never exits cannot pin this thread.
     */
    private static ExecResult captureBounded(Session.Command cmd, String deviceId, String hostname,
                                             int port, DeviceSshDial dial, long deadlineMs)
            throws IOException {
        Thread stderrDrain = new Thread(() -> discardQuietly(cmd.getErrorStream()),
                "device-exec-stderr-" + deviceId);
        stderrDrain.setDaemon(true);
        stderrDrain.start();
        String output;
        Integer exit;
        try {
            output = readBounded(cmd.getInputStream(), MAX_EXEC_OUTPUT_BYTES);
            cmd.join(deadlineMs, TimeUnit.MILLISECONDS);
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

    /** Read at most {@code max} bytes as UTF-8, appending an explicit marker when the remote had
     *  more to say. Never grows without limit. */
    static String readBounded(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int total = 0;
        while (total < max) {
            int n = in.read(buf, 0, Math.min(buf.length, max - total));
            if (n == -1) {
                return out.toString(StandardCharsets.UTF_8);
            }
            out.write(buf, 0, n);
            total += n;
        }
        return out.toString(StandardCharsets.UTF_8)
                + "\n…[output truncated at " + max + " bytes]";
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
        Path keyPath = preflightDialKey(dial);
        var ssh = new SSHClient();
        // FAIL-CLOSED host-key pin — the ONLY verifier. No known-hosts, no PromiscuousVerifier.
        ssh.addHostKeyVerifier(new PinnedHostKeyVerifier(deviceId, dial.hostKeyFp()));
        ssh.setConnectTimeout((int) props.getConnectTimeout().toMillis());
        try {
            ssh.connect(hostname, props.getPort());
            // Per-device dial PRIVATE key from the ESO-synced mount. Loaded into sshj and never
            // logged/persisted/returned. loadDialKey reads the mounted file's bytes only here.
            KeyProvider keys = loadDialKey(ssh, dial, keyPath);
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
     * PRE-CONNECT check that the ESO-synced dial key is actually mounted and readable, so a
     * mis-mounted deployment fails BEFORE a socket is opened and a full SSH transport handshake
     * (host-key verification included) is performed against the device. Returns the key path for
     * {@link #loadDialKey}; the bytes are NOT read here.
     */
    private Path preflightDialKey(DeviceSshDial dial) throws IOException {
        Path keyPath = Path.of(props.getKeyMountPath(), props.getKeyFile());
        if (!Files.isReadable(keyPath)) {
            // Path/provenance only — never the (absent) bytes. k8s_secret_name is the mount hint.
            throw new IOException("dial private key not present at mount for device="
                    + dial.deviceId() + " (k8sSecret=" + dial.k8sSecretName() + ")");
        }
        return keyPath;
    }

    /**
     * Read the per-device dial PRIVATE key from the ESO-synced K8s Secret mount and hand it to sshj
     * as a {@link KeyProvider}, parsed ENTIRELY IN MEMORY (never re-read from / written to disk after
     * this single read). The key text is held only in a transient {@code char[]} that is wiped in a
     * {@code finally}. NOTHING here logs, returns, or persists the key bytes.
     */
    private static KeyProvider loadDialKey(SSHClient ssh, DeviceSshDial dial, Path keyPath)
            throws IOException {
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
            return provider;
        } finally {
            java.util.Arrays.fill(pem, '\0'); // wipe transient key chars
        }
    }

    private static void closeQuietly(SSHClient ssh) {
        try {
            if (ssh.isConnected()) {
                ssh.disconnect();
            }
        } catch (IOException ignore) { //NOPMD EmptyCatchBlock - best-effort close, already failing
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
