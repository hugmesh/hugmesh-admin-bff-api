package net.hugmesh.adminbff.desktop.terminal;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.sshterminal.DeviceSshDial;
import net.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Pins the REAL dial factory's FAIL-CLOSED guarantees that do NOT require a live SSH server:
 * <ul>
 *   <li>NO {@code device_ssh_dial} row for the device ⇒ REFUSE (HostKeyVerificationException);</li>
 *   <li>a row that is NOT {@code ACTIVE} (PENDING/REVOKED) ⇒ REFUSE;</li>
 *   <li>a row with no pinned {@code host_key_fp} ⇒ REFUSE (no TOFU);</li>
 *   <li>the per-device dial PRIVATE key NEVER appears in any log line or in any {@code toString}.</li>
 * </ul>
 * A real handshake (host-key pin match + auth) is exercised by the verifier unit test and the
 * handler deny test against a mock channel; spinning a real sshd is out of scope for the unit slice.
 */
class SshjDeviceSshChannelFactoryTest {

    private static final String DEVICE = "dev-1";
    private static final String HOST = "dev-1.mesh";
    private static final String OPERATOR = "admin-x";
    /** The k8s_secret_name every {@link #dial} row carries — the PER-DEVICE mount subdirectory. */
    private static final String SECRET = "device-ssh-dial-dev-1";

    private DeviceSshDialRepository dials;
    private DeviceTerminalDialProperties props;
    private ListAppender<ILoggingEvent> appender;
    private Logger rootLogger;

    @BeforeEach
    void setUp() {
        dials = mock(DeviceSshDialRepository.class);
        props = new DeviceTerminalDialProperties();
        // Capture EVERY log line emitted during a dial so we can assert the key never leaks.
        rootLogger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        appender = new ListAppender<>();
        // Capture into a thread-safe, snapshot-iterating list. The appender is attached to
        // the ROOT logger at TRACE, so under parallel test execution log lines from other
        // concurrently-running tests append to this list while privateKey_neverAppearsInLogs
        // iterates it — a plain ArrayList raced into ConcurrentModificationException (the test
        // passed in isolation but flaked in the full suite). CopyOnWriteArrayList makes both
        // the concurrent appends and the assertion's iteration safe. (Mirrors the same fix in
        // AdminSshKeyIssuanceServiceTest.)
        appender.list = new java.util.concurrent.CopyOnWriteArrayList<>();
        appender.start();
        rootLogger.addAppender(appender);
        rootLogger.setLevel(Level.TRACE);
    }

    @AfterEach
    void tearDown() {
        rootLogger.detachAppender(appender);
    }

    private SshjDeviceSshChannelFactory factory() {
        return new SshjDeviceSshChannelFactory(dials, props, Schedulers.immediate());
    }

    private static DeviceSshDial dial(String status, String hostKeyFp) {
        return dial(status, hostKeyFp, "ops");
    }

    private static DeviceSshDial dial(String status, String hostKeyFp, String dialUser) {
        return new DeviceSshDial("dial-1", DEVICE, dialUser, "ssh-rsa AAAA...", hostKeyFp,
                "fp-pub", "vault://kv/dev-1", SECRET, null, status, 1L,
                Instant.now(), null);
    }

    /** An ACTIVE, SHA256-pinned, non-root row that differs ONLY in its k8s_secret_name — so a
     *  refusal can be attributed to the per-device key rule and nothing else. */
    private static DeviceSshDial dialWithSecret(String k8sSecretName) {
        return new DeviceSshDial("dial-1", DEVICE, "ops", "ssh-rsa AAAA...", "SHA256:abc",
                "fp-pub", "vault://kv/dev-1", k8sSecretName, null, DeviceSshDial.STATUS_ACTIVE, 1L,
                Instant.now(), null);
    }

    @Test
    void canDial_isTrue() {
        assertThat(factory().canDial()).isTrue();
    }

    @Test
    void refuses_whenNoDialRow() {
        when(dials.findByDeviceId(eq(DEVICE))).thenReturn(Mono.empty());

        StepVerifier.create(factory().open(DEVICE, HOST, OPERATOR, 80, 24))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(DeviceSshChannelFactory.HostKeyVerificationException.class);
                    assertThat(e.getMessage()).contains("no device_ssh_dial row");
                })
                .verify();
    }

    @Test
    void refuses_whenRowNotActive() {
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_PENDING, "aa:bb:cc")));

        StepVerifier.create(factory().open(DEVICE, HOST, OPERATOR, 80, 24))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(DeviceSshChannelFactory.HostKeyVerificationException.class);
                    assertThat(e.getMessage()).contains("not ACTIVE");
                })
                .verify();
    }

    @Test
    void refuses_whenActiveRowHasNoPinnedHostKeyFp() {
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "  ")));

        StepVerifier.create(factory().open(DEVICE, HOST, OPERATOR, 80, 24))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(DeviceSshChannelFactory.HostKeyVerificationException.class);
                    assertThat(e.getMessage()).contains("no pinned host_key_fp");
                })
                .verify();
    }

    // ── D2: the BFF never takes a ROOT shell (open AND exec, from the SAME rule list) ────────

    @Test
    void refuses_whenDialUserIsRoot_open() {
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "SHA256:abc", "root")));

        StepVerifier.create(factory().open(DEVICE, HOST, OPERATOR, 80, 24))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(DeviceSshChannelFactory.HostKeyVerificationException.class);
                    assertThat(e.getMessage()).contains("refusing to dial as root");
                })
                .verify();
    }

    @Test
    void refuses_whenDialUserIsRoot_exec() {
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "SHA256:abc", "ROOT ")));

        StepVerifier.create(factory().exec(DEVICE, HOST, "flatpak install -y org.x.App"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(DeviceSshChannelFactory.HostKeyVerificationException.class);
                    assertThat(e.getMessage()).contains("refusing to exec as root");
                })
                .verify();
    }

    @Test
    void refuses_whenDialUserIsBlank() {
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "SHA256:abc", "  ")));

        StepVerifier.create(factory().open(DEVICE, HOST, OPERATOR, 80, 24))
                .expectError(DeviceSshChannelFactory.HostKeyVerificationException.class)
                .verify();
    }

    @Test
    void isRootOrBlank_recognisesEveryRootSpelling() {
        assertThat(SshjDeviceSshChannelFactory.isRootOrBlank("root")).isTrue();
        assertThat(SshjDeviceSshChannelFactory.isRootOrBlank(" Root ")).isTrue();
        assertThat(SshjDeviceSshChannelFactory.isRootOrBlank("ROOT")).isTrue();
        assertThat(SshjDeviceSshChannelFactory.isRootOrBlank(null)).isTrue();
        assertThat(SshjDeviceSshChannelFactory.isRootOrBlank("")).isTrue();
        assertThat(SshjDeviceSshChannelFactory.isRootOrBlank("snapops")).isFalse();
        // NOT over-broad: a legitimate user whose name merely contains "root" is allowed.
        assertThat(SshjDeviceSshChannelFactory.isRootOrBlank("rootless-ops")).isFalse();
    }

    // ── B2 (XS half): a mis-mounted dial key fails BEFORE a socket is opened ─────────────────

    /** The mount is EMPTY and the target address is TEST-NET-1 with a 30s connect timeout, so if
     *  the readability check ran AFTER {@code connect} (as it did) this would either hang on the
     *  handshake or fail with a connect error — not with the mount message. */
    @Test
    void refusesBeforeOpeningASocket_whenTheDialKeyIsNotMounted(
            @org.junit.jupiter.api.io.TempDir Path emptyMount) {
        props.setKeyMountPath(emptyMount.toString());
        props.setKeyFile("id_dial");
        props.setPort(22);
        props.setConnectTimeout(Duration.ofSeconds(30));
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "SHA256:abc")));

        long startNanos = System.nanoTime();
        StepVerifier.create(factory().open(DEVICE, "192.0.2.1", OPERATOR, 80, 24))
                .expectErrorSatisfies(e -> assertThat(e.getMessage())
                        .contains("per-device dial private key not present at mount")
                        .contains(emptyMount.resolve(SECRET).resolve("id_dial").toString()))
                .verify(Duration.ofSeconds(25));
        // No handshake was attempted: the refusal is immediate, not connect-timeout-shaped.
        assertThat(Duration.ofNanos(System.nanoTime() - startNanos))
                .isLessThan(Duration.ofSeconds(10));
    }

    @Test
    void execAlsoRefusesBeforeOpeningASocket_whenTheDialKeyIsNotMounted(
            @org.junit.jupiter.api.io.TempDir Path emptyMount) {
        props.setKeyMountPath(emptyMount.toString());
        props.setKeyFile("id_dial");
        props.setConnectTimeout(Duration.ofSeconds(30));
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "SHA256:abc")));

        StepVerifier.create(factory().exec(DEVICE, "192.0.2.1", "flatpak install -y org.x.App"))
                .expectErrorSatisfies(e -> assertThat(e.getMessage())
                        .contains("per-device dial private key not present at mount")
                        .contains(emptyMount.resolve(SECRET).resolve("id_dial").toString()))
                .verify(Duration.ofSeconds(25));
    }

    // ── B3: one-shot exec capture is BOUNDED ────────────────────────────────────────────────

    @Test
    void readBounded_capsTheCaptureAndSaysSoInsteadOfGrowingWithoutLimit() throws Exception {
        int cap = SshjDeviceSshChannelFactory.MAX_EXEC_OUTPUT_BYTES;
        byte[] flood = new byte[cap * 4];                 // a device that will not stop talking
        java.util.Arrays.fill(flood, (byte) 'a');

        String captured = SshjDeviceSshChannelFactory.readBounded(
                new java.io.ByteArrayInputStream(flood), cap);

        assertThat(captured).startsWith("aaaa");
        assertThat(captured).contains("[output truncated at " + cap + " bytes]");
        // Bounded: the cap plus the short marker, NOT the 256 KiB the device offered.
        assertThat(captured.length()).isLessThan(cap + 64);
        assertThat(captured.length()).isLessThan(flood.length);
    }

    @Test
    void readBounded_returnsShortOutputVerbatim_noMarker() throws Exception {
        String captured = SshjDeviceSshChannelFactory.readBounded(
                new java.io.ByteArrayInputStream("installed org.x.App\n".getBytes(
                        java.nio.charset.StandardCharsets.UTF_8)),
                SshjDeviceSshChannelFactory.MAX_EXEC_OUTPUT_BYTES);

        assertThat(captured).isEqualTo("installed org.x.App\n");
        assertThat(captured).doesNotContain("truncated");
    }

    // ── H2: stdin/resize are SERIALISED on one worker, never reordered across pool threads ───

    /** The first write blocks for 300ms. Scheduling each write on the POOL (the pre-fix code) lets
     *  writes 2..n run on other boundedElastic threads and land FIRST; a single per-channel Worker
     *  queues them behind it, so the PTY sees the keystrokes in the order they were typed. */
    @Test
    void writeStdin_keystrokesArriveInSubmissionOrder() throws Exception {
        RecordingStdin stdin = new RecordingStdin();
        net.schmizz.sshj.SSHClient ssh = mock(net.schmizz.sshj.SSHClient.class);
        net.schmizz.sshj.connection.channel.direct.Session session =
                mock(net.schmizz.sshj.connection.channel.direct.Session.class);
        net.schmizz.sshj.connection.channel.direct.Session.Shell shell =
                mock(net.schmizz.sshj.connection.channel.direct.Session.Shell.class);
        when(shell.getOutputStream()).thenReturn(stdin);
        when(shell.getInputStream()).thenReturn(new java.io.ByteArrayInputStream(new byte[0]));

        var channel = new SshjDeviceSshChannelFactory.SshjChannel(
                ssh, session, shell, Schedulers.boundedElastic(), DEVICE);
        try {
            for (int i = 0; i < 6; i++) {
                channel.writeStdin(("k" + i).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
            while (stdin.writes.size() < 6 && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            assertThat(stdin.writes).containsExactly("k0", "k1", "k2", "k3", "k4", "k5");
        } finally {
            channel.close();
        }
    }

    /** Records stdin writes in arrival order and stalls the FIRST one, so a scheduler that does not
     *  serialise gets overtaken. */
    private static final class RecordingStdin extends java.io.OutputStream {
        private final java.util.List<String> writes = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final java.util.concurrent.atomic.AtomicBoolean first =
                new java.util.concurrent.atomic.AtomicBoolean(true);

        @Override
        public void write(int b) {
            writes.add(String.valueOf((char) b));
        }

        @Override
        public void write(byte[] b) {
            if (first.compareAndSet(true, false)) {
                try {
                    Thread.sleep(300);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
            writes.add(new String(b, java.nio.charset.StandardCharsets.UTF_8));
        }
    }

    @Test
    void privateKey_neverAppearsInLogs_evenWhenDialFails(@org.junit.jupiter.api.io.TempDir Path tmp)
            throws Exception {
        // A REAL, unique, unencrypted OpenSSH/PEM private key written to the mount. The dial clears
        // the pre-connect mount check, then FAILS at connect (nothing listens on port 1). NB the
        // key BYTES are not parsed on this path — the parse happens after connect — so what this
        // pins is that a failing dial never echoes the mounted key (or the words "PRIVATE KEY")
        // into any log line, including the mount/provenance error text.
        // PER-DEVICE mount: the key lives under the row's OWN k8s_secret_name, not at the root.
        String secretMarker = writeRealRsaPrivateKey(tmp.resolve(SECRET).resolve("id_dial"));
        props.setKeyMountPath(tmp.toString());
        props.setKeyFile("id_dial");
        props.setPort(1); // nothing listening -> connect fails fast
        props.setConnectTimeout(Duration.ofMillis(200));

        // A SHA256: pin, so the row clears refusalReason and the dial really reaches the mount.
        // (It carried an unlabelled "aa:bb:cc:dd" pin, which the later MD5-pin rule refuses before
        // the mount is ever consulted — the test was passing without exercising the key path.)
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "SHA256:abc")));

        StepVerifier.create(factory().open(DEVICE, HOST, OPERATOR, 80, 24))
                .expectError() // connect refused / timed out — but key was read on the way
                .verify(Duration.ofSeconds(15));

        // NO captured log line may contain ANY line of the private key (header or base64 body).
        for (ILoggingEvent ev : appender.list) {
            String msg = ev.getFormattedMessage();
            assertThat(msg).doesNotContain("PRIVATE KEY");
            assertThat(msg).doesNotContain(secretMarker);
        }
    }

    @Test
    void factoryToString_doesNotLeakKeyMaterial() {
        // The factory holds NO key bytes (they are read transiently at dial time), so its toString
        // (and the props it carries) is path/config only — never a secret.
        props.setKeyMountPath("/var/run/secrets/device-ssh-dial");
        assertThat(factory().toString()).doesNotContain("PRIVATE KEY");
        assertThat(props.toString()).doesNotContain("PRIVATE KEY");
    }

    // ── H1: a non-SHA256 pin may not reach a LIVE dial either (both verbs, one rule list) ────

    /** {@code DesktopDialService.activate} refuses to make an MD5 pin ACTIVE — but that is a rule
     *  about the ACTIVATION path only. Any row that reaches ACTIVE another way (a backfill, a
     *  restored dump, a future direct-to-ACTIVE seed) must still be refused AT DIAL TIME, exactly
     *  as the root rule already is on both sides. */
    @Test
    void refuses_whenActivePinIsMd5_open() {
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "MD5:aa:bb:cc:dd")));

        StepVerifier.create(factory().open(DEVICE, HOST, OPERATOR, 80, 24))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(DeviceSshChannelFactory.HostKeyVerificationException.class);
                    assertThat(e.getMessage()).contains("non-SHA256: host_key_fp");
                    assertThat(e.getMessage()).contains("refusing to dial");
                })
                .verify();
    }

    @Test
    void refuses_whenActivePinIsMd5_exec() {
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "MD5:aa:bb:cc:dd")));

        StepVerifier.create(factory().exec(DEVICE, HOST, "flatpak install -y org.x.App"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(DeviceSshChannelFactory.HostKeyVerificationException.class);
                    assertThat(e.getMessage()).contains("non-SHA256: host_key_fp");
                    assertThat(e.getMessage()).contains("refusing to exec");
                })
                .verify();
    }

    /** An UNLABELLED pin is refused too, and for the same reason the activation side refuses it:
     *  "SHA256".equals(labelOf(fp)) is the rule on both sides, so the two can never disagree. */
    @Test
    void refuses_whenActivePinCarriesNoAlgorithmLabel() {
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "aa:bb:cc:dd:ee:ff")));

        StepVerifier.create(factory().open(DEVICE, HOST, OPERATOR, 80, 24))
                .expectErrorSatisfies(e ->
                        assertThat(e.getMessage()).contains("non-SHA256: host_key_fp"))
                .verify();
    }

    // ── B3: the capture is bounded in WALL-CLOCK TIME, not only in memory ────────────────────

    /** THE NEGATIVE case for B3's DoS half. A device that completes auth, opens the session and then goes
     *  silent parks {@code ChannelInputStream.read} on an UNTIMED {@code Object.wait()}; sshj's
     *  {@code setTimeout} does not save us (its Reader swallows SocketTimeoutException). Only the
     *  watchdog does. Asserted: the call RETURNS (by throwing) well inside a small multiple of the
     *  deadline, the abort actually ran, and no stray interrupt is left on this pool thread. */
    // SEPARATE_THREAD so that a REGRESSION here FAILS the build instead of hanging it forever —
    // which is precisely the failure mode this guard exists to prevent.
    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    void readBoundedUnderDeadline_abortsAWedgedDevice_insteadOfParkingTheThreadForever() {
        WedgedInputStream wedged = new WedgedInputStream();
        long deadlineMs = 300L;

        long startNanos = System.nanoTime();
        assertThatThrownBy(() -> SshjDeviceSshChannelFactory.readBoundedUnderDeadline(
                wedged, 64, deadlineMs, wedged::abort))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("exceeded its " + deadlineMs + "ms deadline");
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);

        assertThat(wedged.wasAborted()).as("the deadline watchdog must abort the transport").isTrue();
        assertThat(elapsedMs).as("bounded, not 'forever'").isLessThan(deadlineMs * 20);
        assertThat(Thread.currentThread().isInterrupted())
                .as("the boundedElastic thread goes back to the pool without a stray interrupt")
                .isFalse();
    }

    /** NON-VACUOUSNESS for the test above: WITHOUT the deadline the very same stream really does
     *  park forever, so the assertion is measuring the watchdog and not a stream that would have
     *  returned anyway. */
    @Test
    void readBounded_withoutTheDeadline_reallyDoesParkForever_soTheWatchdogIsLoadBearing()
            throws Exception {
        WedgedInputStream wedged = new WedgedInputStream();
        Thread parked = new Thread(() -> {
            try {
                SshjDeviceSshChannelFactory.readBounded(wedged, 64);
            } catch (IOException ignore) {
                // expected once we abort it at the end of the test
            }
        }, "park-probe");
        parked.setDaemon(true);
        parked.start();
        try {
            parked.join(900L);                       // 3x the deadline the other test uses
            assertThat(parked.isAlive())
                    .as("unbounded readBounded is still parked — the watchdog is what ends it")
                    .isTrue();
        } finally {
            wedged.abort();                          // let the probe thread die
            parked.join(2000L);
        }
    }

    /** The 64 KiB cap bounds MEMORY, not the read. sshj replenishes the channel's local window only
     *  from ChannelInputStream.read, so a reader that STOPPED at the cap would stall any command
     *  whose output exceeds the 2 MiB initial window — it would never exit and the join deadline
     *  would fail an install that used to succeed. Pinned here: the stream is read to EOF. */
    @Test
    void readBounded_keepsReadingPastTheCap_soTheRemoteWindowIsNeverStalled() throws Exception {
        int cap = 1024;
        byte[] flood = new byte[cap * 40];
        java.util.Arrays.fill(flood, (byte) 'a');
        CountingInputStream src = new CountingInputStream(new java.io.ByteArrayInputStream(flood));

        String captured = SshjDeviceSshChannelFactory.readBounded(src, cap);

        assertThat(src.consumed())
                .as("every byte the remote offered was READ (and discarded past the cap)")
                .isEqualTo(flood.length);
        assertThat(captured).contains("[output truncated at " + cap + " bytes]");
        assertThat(captured.length()).as("but only the cap was RETAINED").isLessThan(cap + 64);
    }

    /** The watchdog's abort must not itself block or throw: it closes the socket directly rather
     *  than going through disconnect()/close(), both of which wait on the remote. */
    @Test
    void abortTransport_closesTheSocketDirectly_andNeverThrows() throws Exception {
        net.schmizz.sshj.SSHClient ssh = mock(net.schmizz.sshj.SSHClient.class);
        java.net.Socket socket = new java.net.Socket();
        when(ssh.getSocket()).thenReturn(socket);

        SshjDeviceSshChannelFactory.abortTransport(ssh);
        assertThat(socket.isClosed()).isTrue();

        // idempotent, and null-safe for a client that never connected
        assertThatCode(() -> SshjDeviceSshChannelFactory.abortTransport(ssh))
                .doesNotThrowAnyException();
        net.schmizz.sshj.SSHClient neverConnected = mock(net.schmizz.sshj.SSHClient.class);
        when(neverConnected.getSocket()).thenReturn(null);
        assertThatCode(() -> SshjDeviceSshChannelFactory.abortTransport(neverConnected))
                .doesNotThrowAnyException();
    }

    /** A stdout stream that behaves like sshj's: it never returns and never EOFs until the
     *  transport is aborted underneath it, at which point the read fails. */
    private static final class WedgedInputStream extends InputStream {
        private final CountDownLatch aborted = new CountDownLatch(1);
        private final AtomicBoolean abortCalled = new AtomicBoolean(false);

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n == -1 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            try {
                aborted.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("read interrupted");
            }
            throw new IOException("transport aborted");
        }

        void abort() {
            abortCalled.set(true);
            aborted.countDown();
        }

        boolean wasAborted() {
            return abortCalled.get();
        }
    }

    /** Counts the bytes actually pulled off the delegate, so a test can prove the reader did NOT
     *  stop at the memory cap. */
    private static final class CountingInputStream extends InputStream {
        private final InputStream delegate;
        private int consumed;

        CountingInputStream(InputStream delegate) {
            this.delegate = delegate;
        }

        @Override
        public int read() throws IOException {
            int b = delegate.read();
            if (b != -1) {
                consumed++;
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = delegate.read(b, off, len);
            if (n > 0) {
                consumed += n;
            }
            return n;
        }

        int consumed() {
            return consumed;
        }
    }


    // ── PER-DEVICE KEY MATERIAL (operator answer "per device", 2026-09-10, issue #11 B1) ─────
    //
    // Before the decision, preflightDialKey/loadDialKey both read ONE fixed
    // Path.of(keyMountPath, keyFile) for EVERY device — a single mesh-wide BFF dial key. These
    // pin the two halves of the answer: (a) the path is resolved from the DEVICE's own
    // k8s_secret_name, and (b) a mesh-wide single key is no longer a valid configuration — it
    // fails closed, on both verbs, with a message that says so.

    @Test
    void resolveDialKeyPath_isPerDevice_neverTheOneMeshWidePath() throws Exception {
        props.setKeyMountPath("/var/run/secrets/device-ssh-dial");
        props.setKeyFile("id_dial");

        Path a = SshjDeviceSshChannelFactory.resolveDialKeyPath(props, dialWithSecret("dial-key-a"));
        Path b = SshjDeviceSshChannelFactory.resolveDialKeyPath(props, dialWithSecret("dial-key-b"));

        assertThat(a).isEqualTo(Path.of("/var/run/secrets/device-ssh-dial/dial-key-a/id_dial"));
        assertThat(b).isEqualTo(Path.of("/var/run/secrets/device-ssh-dial/dial-key-b/id_dial"));
        // Two devices, two DIFFERENT files. This is the whole of the decision.
        assertThat(a).isNotEqualTo(b);
        // And neither is the retired mesh-wide path.
        assertThat(a).isNotEqualTo(Path.of("/var/run/secrets/device-ssh-dial/id_dial"));
        assertThat(b).isNotEqualTo(Path.of("/var/run/secrets/device-ssh-dial/id_dial"));
    }

    /** THE fail-closed test for a deployment that has one mesh-wide key today: the key file sits at
     *  the mount ROOT (exactly where the pre-decision code read it) and nowhere else. The dial must
     *  REFUSE — never silently fall back to it — and the refusal must NAME it, because an operator
     *  who is only told "not present" while a key file is plainly on disk looks in the wrong place. */
    @Test
    void refusesAMeshWideKeyAtTheMountRoot_andSaysSo_open(
            @org.junit.jupiter.api.io.TempDir Path mount) throws Exception {
        writeRealRsaPrivateKey(mount.resolve("id_dial"));   // the RETIRED mesh-wide shape
        props.setKeyMountPath(mount.toString());
        props.setKeyFile("id_dial");
        props.setConnectTimeout(Duration.ofSeconds(30));
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "SHA256:abc")));

        long startNanos = System.nanoTime();
        StepVerifier.create(factory().open(DEVICE, "192.0.2.1", OPERATOR, 80, 24))
                .expectErrorSatisfies(e -> assertThat(e.getMessage())
                        .contains("per-device dial private key not present at mount")
                        .contains("MESH-WIDE dial key is mounted at "
                                + mount.resolve("id_dial"))
                        .contains("NO LONGER a valid configuration"))
                .verify(Duration.ofSeconds(25));
        // Refused BEFORE any socket: not connect-timeout-shaped.
        assertThat(Duration.ofNanos(System.nanoTime() - startNanos))
                .isLessThan(Duration.ofSeconds(10));
    }

    @Test
    void refusesAMeshWideKeyAtTheMountRoot_andSaysSo_exec(
            @org.junit.jupiter.api.io.TempDir Path mount) throws Exception {
        writeRealRsaPrivateKey(mount.resolve("id_dial"));
        props.setKeyMountPath(mount.toString());
        props.setKeyFile("id_dial");
        props.setConnectTimeout(Duration.ofSeconds(30));
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "SHA256:abc")));

        StepVerifier.create(factory().exec(DEVICE, "192.0.2.1", "flatpak install -y org.x.App"))
                .expectErrorSatisfies(e -> assertThat(e.getMessage())
                        .contains("per-device dial private key not present at mount")
                        .contains("MESH-WIDE dial key is mounted at "
                                + mount.resolve("id_dial")))
                .verify(Duration.ofSeconds(25));
    }

    /** The mirror image, and what makes the two above non-vacuous: with the key at the PER-DEVICE
     *  path and NOTHING at the mount root, the mount check PASSES and the dial goes on to fail at
     *  connect instead. A regression that resolved the flat mesh-wide path would fail here. */
    @Test
    void acceptsTheKeyAtThePerDeviceMount_andProceedsPastTheMountCheck(
            @org.junit.jupiter.api.io.TempDir Path mount) throws Exception {
        writeRealRsaPrivateKey(mount.resolve(SECRET).resolve("id_dial"));
        assertThat(Files.exists(mount.resolve("id_dial"))).isFalse();   // no mesh-wide key anywhere
        props.setKeyMountPath(mount.toString());
        props.setKeyFile("id_dial");
        props.setPort(1);                                   // nothing listening -> connect fails
        props.setConnectTimeout(Duration.ofMillis(300));
        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "SHA256:abc")));

        StepVerifier.create(factory().open(DEVICE, "127.0.0.1", OPERATOR, 80, 24))
                .expectErrorSatisfies(e -> assertThat(String.valueOf(e.getMessage()))
                        .doesNotContain("not present at mount")
                        .doesNotContain("k8s_secret_name"))
                .verify(Duration.ofSeconds(20));
    }

    /** A row that names NO Secret is exactly the shape a mesh-wide deployment has. Refused by the
     *  ONE shared precondition list, so BOTH verbs refuse it, before any dispatch. */
    @Test
    void refuses_whenTheRowNamesNoK8sSecret_open() {
        when(dials.findByDeviceId(eq(DEVICE))).thenReturn(Mono.just(dialWithSecret(null)));

        StepVerifier.create(factory().open(DEVICE, HOST, OPERATOR, 80, 24))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(DeviceSshChannelFactory.HostKeyVerificationException.class);
                    assertThat(e.getMessage())
                            .contains("names no k8s_secret_name")
                            .contains("mesh-wide dial key is no longer a valid configuration")
                            .contains("refusing to dial");
                })
                .verify();
    }

    @Test
    void refuses_whenTheRowNamesNoK8sSecret_exec() {
        when(dials.findByDeviceId(eq(DEVICE))).thenReturn(Mono.just(dialWithSecret("   ")));

        StepVerifier.create(factory().exec(DEVICE, HOST, "flatpak install -y org.x.App"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(DeviceSshChannelFactory.HostKeyVerificationException.class);
                    assertThat(e.getMessage())
                            .contains("names no k8s_secret_name")
                            .contains("refusing to exec");
                })
                .verify();
    }

    /** k8s_secret_name becomes a PATH SEGMENT, and it is seeded from the image-build ingest (an
     *  internal-token surface). It is matched against the real DNS-1123 Secret-name rule, so a
     *  traversal, a separator, an absolute path or padding can never reach the filesystem. */
    @Test
    void refusesEveryMalformedK8sSecretName_soNoRowCanEscapeTheMount() {
        String[] malformed = {
            "..", "../..", "../../etc/ssl", "a/b", "/etc/ssl", "\\\\etc", "dial key",
            " dial-key-a", "dial-key-a ", "-dial", "dial-", ".dial", "dial.", "Dial-Key",
            "dial_key", "dial..key", "", "  ", "a".repeat(254),
        };
        for (String name : malformed) {
            assertThat(SshjDeviceSshChannelFactory.dialKeyIdentityRefusal(dialWithSecret(name)))
                    .as("must refuse k8s_secret_name=<%s>", name)
                    .isNotNull();
            assertThatThrownBy(() ->
                    SshjDeviceSshChannelFactory.resolveDialKeyPath(props, dialWithSecret(name)))
                    .as("must refuse to resolve a path for k8s_secret_name=<%s>", name)
                    .isInstanceOf(IOException.class);
        }
    }

    /** Not over-broad: every shape a real ESO-synced Secret name takes still resolves. */
    @Test
    void acceptsEveryLegalK8sSecretName() throws Exception {
        props.setKeyMountPath("/mnt");
        props.setKeyFile("id_dial");
        for (String name : new String[] {
            "device-ssh-dial-dev-1", "dial", "d1", "a.b.c", "dial-key-0000", "a".repeat(253),
        }) {
            assertThat(SshjDeviceSshChannelFactory.dialKeyIdentityRefusal(dialWithSecret(name)))
                    .as("must ACCEPT k8s_secret_name=<%s>", name)
                    .isNull();
            assertThat(SshjDeviceSshChannelFactory.resolveDialKeyPath(props, dialWithSecret(name)))
                    .isEqualTo(Path.of("/mnt", name, "id_dial"));
        }
    }

    /** The SECOND, independent guard: whatever the row says, the resolved file must still live
     *  under the configured mount. Here the escape comes from the key-FILE setting, which the
     *  Secret-name rule does not police at all. */
    @Test
    void refusesAResolvedPathThatEscapesTheMount_evenWithALegalSecretName() {
        props.setKeyMountPath("/var/run/secrets/device-ssh-dial");
        props.setKeyFile("../../../etc/shadow");

        assertThatThrownBy(() ->
                SshjDeviceSshChannelFactory.resolveDialKeyPath(props, dialWithSecret("dial-key-a")))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("escapes the mount");
    }

    /** The startup half of "a mesh-wide key is not a valid configuration": DeviceTerminalConfig
     *  logs this at ERROR when the flag is flipped on with the retired flat mount, so the operator
     *  learns at startup rather than on the first dial. */
    @Test
    void meshWideKeyHint_namesTheLegacyFile_andIsEmptyOnACleanMount(
            @org.junit.jupiter.api.io.TempDir Path mount) throws Exception {
        props.setKeyMountPath(mount.toString());
        props.setKeyFile("id_dial");

        assertThat(SshjDeviceSshChannelFactory.meshWideKeyHint(props)).isEmpty();

        // A per-device key does NOT trip it — only a key at the mount ROOT does.
        writeRealRsaPrivateKey(mount.resolve(SECRET).resolve("id_dial"));
        assertThat(SshjDeviceSshChannelFactory.meshWideKeyHint(props)).isEmpty();

        writeRealRsaPrivateKey(mount.resolve("id_dial"));
        assertThat(SshjDeviceSshChannelFactory.meshWideKeyHint(props))
                .contains("MESH-WIDE dial key is mounted at " + mount.resolve("id_dial"))
                .contains("NO LONGER a valid configuration")
                .contains(mount.resolve("<k8s_secret_name>").resolve("id_dial").toString())
                .doesNotContain("PRIVATE KEY");
    }


    /** {@link SshjDeviceSshChannelFactory#loadDialKey} is the SECOND reader of the key, and it runs
     *  only AFTER a successful connect — no unit test can reach it through a dial. Called directly
     *  here so its per-device resolution is measured rather than assumed: a regression that reverted
     *  ONLY this reader to the mesh-wide flat path would otherwise pass every other test in the
     *  class. A fresh {@code SSHClient} is enough — it builds its transport (and therefore its key
     *  provider factories) in the constructor, so nothing is dialed. */
    @Test
    void loadDialKey_readsThePerDeviceKey_andNotTheMeshWideOne(
            @org.junit.jupiter.api.io.TempDir Path mount) throws Exception {
        writeRealRsaPrivateKey(mount.resolve(SECRET).resolve("id_dial"));
        props.setKeyMountPath(mount.toString());
        props.setKeyFile("id_dial");

        net.schmizz.sshj.SSHClient ssh = new net.schmizz.sshj.SSHClient();
        try {
            var provider = factory().loadDialKey(ssh, dial(DeviceSshDial.STATUS_ACTIVE, "SHA256:abc"));
            // Found, read and PARSED from <mount>/<k8s_secret_name>/id_dial.
            assertThat(provider).isNotNull();
            // AND a REGRESSION TEST for the lazy-provider bug this test found. These three calls
            // are made HERE, after loadDialKey returned — i.e. after its finally zeroed the char[]
            // — which is exactly when ssh.authPublickey() makes them on the real dial path. They
            // are asserted BEFORE the type assertion below ON PURPOSE: they must fail on their own
            // BEHAVIOUR if the lazy provider comes back, not merely because the class changed.
            // MEASURED against sshj 0.40.0 on this classpath (a standalone probe replaying the
            // pre-fix sequence): getPrivate() threw
            //   java.io.IOException: Supported PEM Key Type not found for header [header not found]
            // so public-key auth could never have succeeded.
            assertThat(provider.getPrivate()).isNotNull();
            assertThat(provider.getPublic()).isNotNull();
            assertThat(provider.getType()).isEqualTo(net.schmizz.sshj.common.KeyType.RSA);
            // Belt-and-braces on the same rule: nothing lazy, nothing holding a Reader, escapes.
            assertThat(provider).isNotInstanceOf(
                    net.schmizz.sshj.userauth.keyprovider.FileKeyProvider.class);
        } finally {
            ssh.close();
        }
    }

    /** The other half: with the key ONLY at the mount root (the retired mesh-wide shape), this
     *  reader must NOT find it. */
    @Test
    void loadDialKey_refusesToFallBackToAMeshWideKeyAtTheMountRoot(
            @org.junit.jupiter.api.io.TempDir Path mount) throws Exception {
        writeRealRsaPrivateKey(mount.resolve("id_dial"));
        props.setKeyMountPath(mount.toString());
        props.setKeyFile("id_dial");

        net.schmizz.sshj.SSHClient ssh = new net.schmizz.sshj.SSHClient();
        try {
            assertThatThrownBy(() ->
                    factory().loadDialKey(ssh, dial(DeviceSshDial.STATUS_ACTIVE, "SHA256:abc")))
                    .isInstanceOf(IOException.class);
        } finally {
            ssh.close();
        }
    }

    /** And it refuses a row that names no Secret at all, on its own — the identity rule is not
     *  something only {@code refusalReason} enforces. */
    @Test
    void loadDialKey_refusesARowThatNamesNoSecret(@org.junit.jupiter.api.io.TempDir Path mount)
            throws Exception {
        props.setKeyMountPath(mount.toString());
        props.setKeyFile("id_dial");

        net.schmizz.sshj.SSHClient ssh = new net.schmizz.sshj.SSHClient();
        try {
            assertThatThrownBy(() -> factory().loadDialKey(ssh, dialWithSecret("")))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("names no k8s_secret_name");
        } finally {
            ssh.close();
        }
    }

    /** Writes a real unencrypted RSA private key (classic PEM) and returns a distinctive substring
     *  of its base64 body to scan logs for. */
    private static String writeRealRsaPrivateKey(Path path) throws Exception {
        java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        java.security.KeyPair kp = g.generateKeyPair();
        String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(kp.getPrivate().getEncoded());
        String pem = "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
        Files.createDirectories(path.getParent());
        Files.writeString(path, pem);
        // a stable 32-char slice of the body that uniquely identifies THIS key
        String body = b64.replace("\n", "");
        return body.substring(0, Math.min(32, body.length()));
    }
}
