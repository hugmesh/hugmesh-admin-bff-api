package systems.hugmesh.adminbff.desktop.terminal;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Factory;
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
import systems.hugmesh.adminbff.sshterminal.DeviceSshDial;
import systems.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
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
 * <h3>Threading</h3>
 * Every sshj call (connect, auth, key read, PTY alloc, stream copy, close) is BLOCKING and is
 * therefore executed on {@link Schedulers#boundedElastic()} — never the Netty event loop. The output
 * {@link Flux} is produced by a blocking read loop {@code subscribeOn} boundedElastic; stdin/resize
 * writes are dispatched to boundedElastic too.
 */
public class SshjDeviceSshChannelFactory implements DeviceSshChannelFactory {

    private static final Logger log = LoggerFactory.getLogger(SshjDeviceSshChannelFactory.class);

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
                // Verify ACTIVE + pinned host-key before dispatching the blocking dial.
                .flatMap(dial -> dialIfActive(dial, deviceId, hostname, cols, rows));
    }

    @Override
    public Mono<ExecResult> exec(String deviceId, String hostname, String command) {
        // SAME fail-closed ACTIVE-dial-row + pinned-host-key gate as open() — install rides the SAME
        // pinned device_ssh_dial trust path as the terminal (no second TOFU surface).
        return dials.findByDeviceId(deviceId)
                .switchIfEmpty(Mono.error(new HostKeyVerificationException(
                        "no device_ssh_dial row for device=" + deviceId + " — refusing to exec")))
                // Verify ACTIVE + pinned host-key before dispatching the blocking exec.
                .flatMap(dial -> execIfActive(dial, deviceId, hostname, command));
    }

    /** Gate the dial on ACTIVE status + pinned host-key then dispatch the blocking dial on ioScheduler. */
    private Mono<Channel> dialIfActive(DeviceSshDial dial, String deviceId, String hostname,
                                       int cols, int rows) {
        if (!dial.isActive()) {
            return Mono.error(new HostKeyVerificationException(
                    "device_ssh_dial for device=" + deviceId + " is status="
                    + dial.status() + " (not ACTIVE) — refusing to dial"));
        }
        if (dial.hostKeyFp() == null || dial.hostKeyFp().isBlank()) {
            return Mono.error(new HostKeyVerificationException(
                    "device_ssh_dial for device=" + deviceId
                    + " has no pinned host_key_fp — refusing to dial (no TOFU)"));
        }
        return Mono.fromCallable(() -> dial(deviceId, hostname, dial, cols, rows))
                .subscribeOn(ioScheduler);
    }

    /** Gate the exec on ACTIVE status + pinned host-key then dispatch the blocking exec on ioScheduler. */
    private Mono<ExecResult> execIfActive(DeviceSshDial dial, String deviceId,
                                          String hostname, String command) {
        if (!dial.isActive()) {
            return Mono.error(new HostKeyVerificationException(
                    "device_ssh_dial for device=" + deviceId + " is status="
                    + dial.status() + " (not ACTIVE) — refusing to exec"));
        }
        if (dial.hostKeyFp() == null || dial.hostKeyFp().isBlank()) {
            return Mono.error(new HostKeyVerificationException(
                    "device_ssh_dial for device=" + deviceId
                    + " has no pinned host_key_fp — refusing to exec (no TOFU)"));
        }
        return Mono.fromCallable(() -> execBlocking(deviceId, hostname, dial, command))
                .subscribeOn(ioScheduler);
    }

    /** Blocking: connect + pin-verify host key + auth + run ONE non-interactive command, capturing
     *  exit + output. Runs on {@link #ioScheduler}. */
    private ExecResult execBlocking(String deviceId, String hostname, DeviceSshDial dial, String command)
            throws IOException {
        var ssh = new SSHClient();
        ssh.addHostKeyVerifier(new PinnedHostKeyVerifier(deviceId, dial.hostKeyFp()));
        ssh.setConnectTimeout((int) props.getConnectTimeout().toMillis());
        try {
            ssh.connect(hostname, props.getPort());
            KeyProvider keys = loadDialKey(ssh, dial);
            ssh.authPublickey(dial.dialUser(), keys);
            Session session = ssh.startSession();
            Session.Command cmd = session.exec(command);
            String output = net.schmizz.sshj.common.IOUtils.readFully(cmd.getInputStream()).toString();
            cmd.join();
            Integer exit = cmd.getExitStatus();
            log.info("[desktop-remote-install] (sshj) one-shot exec device={} host={}:{} dialUser={} "
                    + "exit={} (host-key PINNED)", deviceId, hostname, props.getPort(), dial.dialUser(),
                    exit);
            return new ExecResult(exit, output);
        } catch (Throwable t) {
            closeQuietly(ssh);
            throw t;
        } finally {
            closeQuietly(ssh);
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
        var ssh = new SSHClient();
        // FAIL-CLOSED host-key pin — the ONLY verifier. No known-hosts, no PromiscuousVerifier.
        ssh.addHostKeyVerifier(new PinnedHostKeyVerifier(deviceId, dial.hostKeyFp()));
        ssh.setConnectTimeout((int) props.getConnectTimeout().toMillis());
        try {
            ssh.connect(hostname, props.getPort());
            // Per-device dial PRIVATE key from the ESO-synced mount. Loaded into sshj and never
            // logged/persisted/returned. loadPrivateKey reads the mounted file's bytes only here.
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
     * Read the per-device dial PRIVATE key from the ESO-synced K8s Secret mount and hand it to sshj
     * as a {@link KeyProvider}, parsed ENTIRELY IN MEMORY (never re-read from / written to disk after
     * this single read). The key text is held only in a transient {@code char[]} that is wiped in a
     * {@code finally}. NOTHING here logs, returns, or persists the key bytes.
     */
    private KeyProvider loadDialKey(SSHClient ssh, DeviceSshDial dial) throws IOException {
        Path keyPath = Path.of(props.getKeyMountPath(), props.getKeyFile());
        if (!Files.isReadable(keyPath)) {
            // Path/provenance only — never the (absent) bytes. k8s_secret_name is the mount hint.
            throw new IOException("dial private key not present at mount for device="
                    + dial.deviceId() + " (k8sSecret=" + dial.k8sSecretName() + ")");
        }
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
     * #writeStdin}/{@link #resize}/{@link #close} dispatch to the scheduler. NO key material is held
     * here — only the live shell streams.
     */
    private static final class SshjChannel implements Channel {

        private final SSHClient ssh;
        private final Session session;
        private final Session.Shell shell;
        private final OutputStream stdin;
        private final InputStream stdout;
        private final Scheduler scheduler;
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
            this.deviceId = deviceId;
        }

        @Override
        public void writeStdin(byte[] data) {
            scheduler.schedule(() -> {
                try {
                    stdin.write(data);
                    stdin.flush();
                } catch (IOException e) {
                    close();
                }
            });
        }

        @Override
        public void resize(int cols, int rows) {
            scheduler.schedule(() -> {
                try {
                    shell.changeWindowDimensions(Math.max(1, cols), Math.max(1, rows), 0, 0);
                } catch (IOException e) {
                    // a resize failure should not kill the session by itself
                    log.debug("[device-terminal] (sshj) resize failed device={}", deviceId);
                }
            });
        }

        @Override
        public Flux<byte[]> output() {
            // Read stdout bytes in a blocking loop, emitting chunks until EOF or close.
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
                // Schedule teardown on the dedicated I/O thread (never block the caller).
                scheduler.schedule(this::tearDownChannel);
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
            log.info("[device-terminal] (sshj) channel closed device={}", deviceId);
        }
    }
}
