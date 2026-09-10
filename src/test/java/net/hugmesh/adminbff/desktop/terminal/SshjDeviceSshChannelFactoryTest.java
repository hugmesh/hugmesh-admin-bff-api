package net.hugmesh.adminbff.desktop.terminal;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.sshterminal.DeviceSshDial;
import net.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
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
                "fp-pub", "vault://kv/dev-1", "device-ssh-dial-dev-1", null, status, 1L,
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
                        .contains("dial private key not present at mount"))
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
                        .contains("dial private key not present at mount"))
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
        String secretMarker = writeRealRsaPrivateKey(tmp.resolve("id_dial"));
        props.setKeyMountPath(tmp.toString());
        props.setKeyFile("id_dial");
        props.setPort(1); // nothing listening -> connect fails fast
        props.setConnectTimeout(Duration.ofMillis(200));

        when(dials.findByDeviceId(eq(DEVICE)))
                .thenReturn(Mono.just(dial(DeviceSshDial.STATUS_ACTIVE, "aa:bb:cc:dd")));

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

    /** Writes a real unencrypted RSA private key (classic PEM) and returns a distinctive substring
     *  of its base64 body to scan logs for. */
    private static String writeRealRsaPrivateKey(Path path) throws Exception {
        java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        java.security.KeyPair kp = g.generateKeyPair();
        String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(kp.getPrivate().getEncoded());
        String pem = "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
        Files.writeString(path, pem);
        // a stable 32-char slice of the body that uniquely identifies THIS key
        String body = b64.replace("\n", "");
        return body.substring(0, Math.min(32, body.length()));
    }
}
