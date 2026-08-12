package net.hugmesh.adminbff.desktop.terminal;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import net.hugmesh.adminbff.desktop.DesktopRemoteInstallService;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

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
