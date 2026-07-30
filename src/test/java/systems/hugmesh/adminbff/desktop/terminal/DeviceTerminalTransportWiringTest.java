package systems.hugmesh.adminbff.desktop.terminal;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import systems.hugmesh.adminbff.desktop.DesktopRemoteInstallService;
import systems.hugmesh.adminbff.device.DeviceRegistryRepository;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Pins the SHIPS-DARK {@code @ConditionalOnProperty} wiring of the device-terminal LIVE transport
 * on the REAL {@link DeviceTerminalConfig} (NOT a copy of it — so it cannot drift), mirroring
 * {@code DesktopClientWiringTest}. With NO {@code app.device-terminal.enabled} property (the
 * DEFAULT), the transport bean is the no-dial {@link StubDeviceSshTransport} and the real
 * {@link SshDeviceTerminalTransport} bean is ABSENT; flipping the flag on swaps in the real
 * transport and the stub is gone. The channel-dial seam ALWAYS defaults to the fail-closed
 * {@link UnconfiguredDeviceSshChannelFactory} (the FLAGGED host-key decision), so even flag-on no
 * real device is dialed. The WS-handler collaborators are mocked so the FULL real config wires.
 */
class DeviceTerminalTransportWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(DeviceTerminalConfig.class)
            // collaborators the real WS-handler bean needs (mocked — this test pins WIRING, not behavior)
            .withBean(DesktopRemoteInstallService.class, () -> mock(DesktopRemoteInstallService.class))
            .withBean(DeviceRegistryRepository.class, () -> mock(DeviceRegistryRepository.class))
            .withBean(DomainRegistry.class, () -> new DomainRegistry("", ""))
            .withBean(WorkloadStepUpService.class, () -> mock(WorkloadStepUpService.class))
            // A5 step-up collaborators the WS handler now also needs (the co-equal MFA leg).
            .withBean(DeviceTerminalStepUpGate.class, () -> mock(DeviceTerminalStepUpGate.class))
            .withBean(systems.hugmesh.authcore.casdoor.MfaStepUpService.class,
                    () -> mock(systems.hugmesh.authcore.casdoor.MfaStepUpService.class))
            .withBean(ObjectMapper.class, ObjectMapper::new);

    // ── DEFAULT (no property) -> the STUB transport (ships dark); real transport ABSENT ──

    @Test
    void transport_defaultsToStub_shipsDark_realBeanAbsent() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(DeviceSshTransport.class);
            DeviceSshTransport bean = ctx.getBean(DeviceSshTransport.class);
            assertThat(bean).isInstanceOf(StubDeviceSshTransport.class);
            assertThat(bean.isReal()).isFalse();
            // The REAL transport bean must NOT be in the context by default.
            assertThat(ctx).doesNotHaveBean(SshDeviceTerminalTransport.class);
        });
    }

    @Test
    void channelFactory_defaultsToUnconfigured_failsClosed() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(DeviceSshChannelFactory.class);
            DeviceSshChannelFactory f = ctx.getBean(DeviceSshChannelFactory.class);
            assertThat(f).isInstanceOf(UnconfiguredDeviceSshChannelFactory.class);
            assertThat(f.canDial()).isFalse();
        });
    }

    // ── enabled=true -> the REAL transport; stub ABSENT (mutually exclusive) ─────────

    @Test
    void transport_whenEnabled_isRealTransport_stubAbsent_butStillCannotDial() {
        runner.withPropertyValues("app.device-terminal.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(DeviceSshTransport.class);
            DeviceSshTransport bean = ctx.getBean(DeviceSshTransport.class);
            assertThat(bean).isInstanceOf(SshDeviceTerminalTransport.class);
            assertThat(bean.isReal()).isTrue();
            // The stub bean is gone when the real one is wired (mutually exclusive).
            assertThat(ctx).doesNotHaveBean(StubDeviceSshTransport.class);
            // …but even enabled, the dial seam still fails closed (FLAGGED host-key decision).
            assertThat(ctx.getBean(DeviceSshChannelFactory.class).canDial()).isFalse();
        });
    }
}
