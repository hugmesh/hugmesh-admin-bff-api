package systems.hugmesh.adminbff.desktop.terminal;

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
import systems.hugmesh.adminbff.sshterminal.DeviceSshDial;
import systems.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;

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
        return new DeviceSshDial("dial-1", DEVICE, "ops", "ssh-rsa AAAA...", hostKeyFp,
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

    @Test
    void privateKey_neverAppearsInLogs_evenWhenDialFails(@org.junit.jupiter.api.io.TempDir Path tmp)
            throws Exception {
        // A REAL, unique, unencrypted OpenSSH/PEM private key written to the mount. The dial will
        // FAIL (the host 127.0.0.1:1 is not an sshd), but loadDialKey reads the key first — so this
        // proves the key material never reaches any log line.
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
