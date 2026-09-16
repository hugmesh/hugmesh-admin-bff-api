package net.hugmesh.adminbff.desktop.terminal;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import net.hugmesh.adminbff.desktop.DesktopRemoteInstallService;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Pins the SECOND, INDEPENDENT ships-dark gate ({@code app.device-terminal.dial.enabled}) on the
 * REAL {@link DeviceTerminalConfig} (NOT a copy — so it cannot drift). The default dial seam is the
 * fail-closed {@link UnconfiguredDeviceSshChannelFactory} (flag absent/false); only when
 * {@code app.device-terminal.dial.enabled=true} is the host-key-pinned
 * {@link SshjDeviceSshChannelFactory} wired and {@link DeviceSshChannelFactory#canDial()} flips true.
 * The transport-level gate ({@code app.device-terminal.enabled}) is orthogonal — proven here that
 * the dial gate can be on while the transport stays the stub, and vice-versa.
 */
class DeviceTerminalDialWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(DeviceTerminalConfig.class)
            .withBean(DesktopRemoteInstallService.class, () -> mock(DesktopRemoteInstallService.class))
            .withBean(DeviceRegistryRepository.class, () -> mock(DeviceRegistryRepository.class))
            .withBean(DomainRegistry.class, () -> new DomainRegistry("", ""))
            .withBean(WorkloadStepUpService.class, () -> mock(WorkloadStepUpService.class))
            // A5 step-up collaborators the WS handler now also needs (the co-equal MFA leg).
            .withBean(DeviceTerminalStepUpGate.class, () -> mock(DeviceTerminalStepUpGate.class))
            .withBean(net.hugmesh.authcore.casdoor.MfaStepUpService.class,
                    () -> mock(net.hugmesh.authcore.casdoor.MfaStepUpService.class))
            // the sshj factory bean depends on the dial repo — supply a mock for the wiring slice
            .withBean(DeviceSshDialRepository.class, () -> mock(DeviceSshDialRepository.class))
            .withBean(ObjectMapper.class, ObjectMapper::new);

    @Test
    void dialDefaultsToUnconfigured_failsClosed_sshjBeanAbsent() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(DeviceSshChannelFactory.class);
            DeviceSshChannelFactory f = ctx.getBean(DeviceSshChannelFactory.class);
            assertThat(f).isInstanceOf(UnconfiguredDeviceSshChannelFactory.class);
            assertThat(f.canDial()).isFalse();
            assertThat(ctx).doesNotHaveBean(SshjDeviceSshChannelFactory.class);
        });
    }

    @Test
    void transportEnabledButDialDisabled_stillFailsClosed() {
        runner.withPropertyValues("app.device-terminal.enabled=true").run(ctx -> {
            // Real transport bean, but the dial seam is STILL the fail-closed unconfigured factory.
            assertThat(ctx.getBean(DeviceSshTransport.class)).isInstanceOf(SshDeviceTerminalTransport.class);
            assertThat(ctx.getBean(DeviceSshChannelFactory.class))
                    .isInstanceOf(UnconfiguredDeviceSshChannelFactory.class);
            assertThat(ctx.getBean(DeviceSshChannelFactory.class).canDial()).isFalse();
            assertThat(ctx).doesNotHaveBean(SshjDeviceSshChannelFactory.class);
        });
    }

    @Test
    void dialEnabled_wiresSshjFactory_canDialTrue_unconfiguredBacksOff() {
        runner.withPropertyValues("app.device-terminal.dial.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(DeviceSshChannelFactory.class);
            DeviceSshChannelFactory f = ctx.getBean(DeviceSshChannelFactory.class);
            assertThat(f).isInstanceOf(SshjDeviceSshChannelFactory.class);
            assertThat(f.canDial()).isTrue();
            assertThat(ctx).doesNotHaveBean(UnconfiguredDeviceSshChannelFactory.class);
        });
    }

    /**
     * The wiring ANNOUNCES the explicit algorithm policy (hugmesh-admin-bff-api#11 H3) at STARTUP,
     * the same "learn it now, not at 3am on the first dial" treatment the mesh-wide-key hint gets.
     * Without this, "the operator can see which algorithms the dial negotiates" would be a claim no
     * test measures — and a wiring that silently stopped logging it would look identical.
     */
    @Test
    void dialEnabled_announcesTheExplicitAlgorithmPolicy_atStartup() {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(DeviceTerminalConfig.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            runner.withPropertyValues("app.device-terminal.dial.enabled=true").run(ctx ->
                    assertThat(ctx.getBean(DeviceSshChannelFactory.class).canDial()).isTrue());

            String logged = appender.list.stream()
                    .map(ILoggingEvent::getFormattedMessage)
                    .collect(Collectors.joining("\n"));
            assertThat(logged)
                    .contains("dial algorithm policy")
                    .contains("curve25519-sha256")
                    .contains("ssh-ed25519")
                    .contains("aes256-gcm@openssh.com")
                    .contains("hmac-sha2-512-etm@openssh.com");
            // sshj's defaults are NOT what is announced (nor negotiated).
            assertThat(logged).doesNotContain("ssh-rsa").doesNotContain("arcfour");
            // Every policy algorithm resolves on this build, the default key-file is one plain
            // name and nothing is mounted flat, so NO ERROR-level event may fire on the happy
            // path. (The ERROR half itself is pinned by the announceDialPolicy_* tests below —
            // through the real wiring this assertion can only ever see the happy path.)
            assertThat(appender.list.stream()
                    .filter(e -> e.getLevel() == ch.qos.logback.classic.Level.ERROR)
                    .map(ILoggingEvent::getFormattedMessage).toList())
                    .as("no fail-closed condition exists on this classpath")
                    .isEmpty();
        } finally {
            logger.detachAppender(appender);
            appender.stop();
        }
    }

    // ── The ERROR half of the startup announcement, fed through the seam the bean calls ──────────
    //
    // The 2026-09-16 skeptic pass on this branch found that disabling the UNAVAILABLE check in the
    // wiring left every test green: the only assertion was a NEGATIVE one on a condition this sshj
    // build cannot produce. These three feed the condition in and assert the ERROR fires.

    @Test
    void announceDialPolicy_logsAnError_whenThisSshjBuildLacksAPolicyAlgorithm() {
        List<ILoggingEvent> errors = capture(() -> DeviceTerminalConfig.announceDialPolicy(
                new DeviceTerminalDialProperties(), List.of("curve25519-sha256", "ssh-ed25519")));

        assertThat(errors).hasSize(1);
        assertThat(errors.get(0).getFormattedMessage())
                .contains("DIAL ALGORITHM POLICY UNAVAILABLE")
                .contains("curve25519-sha256")
                .contains("ssh-ed25519")
                .contains("FAIL CLOSED");
    }

    @Test
    void announceDialPolicy_logsAnError_whenTheKeyFileSettingClimbsOutOfTheDeviceMount() {
        DeviceTerminalDialProperties props = new DeviceTerminalDialProperties();
        props.setKeyFile("../id_dial");   // the retired mesh-wide file, reached through config

        List<ILoggingEvent> errors = capture(() ->
                DeviceTerminalConfig.announceDialPolicy(props, List.of()));

        assertThat(errors).hasSize(1);
        assertThat(errors.get(0).getFormattedMessage())
                .contains("DIAL KEY-FILE SETTING REFUSED")
                .contains("not a single plain file name")
                .contains("../id_dial")
                .contains("FAIL CLOSED");
    }

    /** The mesh-wide startup ERROR the lane could only prove at the string-helper level: with a
     *  real flat key at the mount root, the announcement the bean makes carries it at ERROR. */
    @Test
    void announceDialPolicy_logsAnError_whenAMeshWideKeyIsMountedFlat(
            @org.junit.jupiter.api.io.TempDir Path mount) throws Exception {
        Files.writeString(mount.resolve("id_dial"), "-----BEGIN PRIVATE KEY-----\nQUJD\n");
        DeviceTerminalDialProperties props = new DeviceTerminalDialProperties();
        props.setKeyMountPath(mount.toString());
        props.setKeyFile("id_dial");

        List<ILoggingEvent> errors = capture(() ->
                DeviceTerminalConfig.announceDialPolicy(props, List.of()));

        assertThat(errors).hasSize(1);
        assertThat(errors.get(0).getFormattedMessage())
                .contains("MESH-WIDE DIAL KEY DETECTED")
                .contains(mount.resolve("id_dial").toString())
                .doesNotContain("QUJD");   // a PATH, never the bytes
    }

    @Test
    void announceDialPolicy_isSilentAtError_onACleanDeployment(
            @org.junit.jupiter.api.io.TempDir Path mount) {
        DeviceTerminalDialProperties props = new DeviceTerminalDialProperties();
        props.setKeyMountPath(mount.toString());   // empty parent: no flat key, no device dirs yet

        List<ILoggingEvent> errors = capture(() ->
                DeviceTerminalConfig.announceDialPolicy(props, List.of()));

        assertThat(errors).isEmpty();
    }

    /** Runs {@code body} with a ListAppender on the config's logger; returns the ERROR events. */
    private static List<ILoggingEvent> capture(Runnable body) {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(DeviceTerminalConfig.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            body.run();
            return appender.list.stream()
                    .filter(e -> e.getLevel() == ch.qos.logback.classic.Level.ERROR)
                    .toList();
        } finally {
            logger.detachAppender(appender);
            appender.stop();
        }
    }

    @Test
    void bothGatesOn_realTransport_overSshjPinnedDial() {
        runner.withPropertyValues(
                "app.device-terminal.enabled=true",
                "app.device-terminal.dial.enabled=true").run(ctx -> {
            assertThat(ctx.getBean(DeviceSshTransport.class)).isInstanceOf(SshDeviceTerminalTransport.class);
            assertThat(ctx.getBean(DeviceSshTransport.class).isReal()).isTrue();
            DeviceSshChannelFactory f = ctx.getBean(DeviceSshChannelFactory.class);
            assertThat(f).isInstanceOf(SshjDeviceSshChannelFactory.class);
            assertThat(f.canDial()).isTrue();
        });
    }
}
