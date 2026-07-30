package systems.hugmesh.adminbff.desktop.terminal;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.reactive.handler.SimpleUrlHandlerMapping;
import org.springframework.web.reactive.socket.WebSocketHandler;
import org.springframework.web.reactive.socket.server.support.WebSocketHandlerAdapter;
import systems.hugmesh.adminbff.desktop.DesktopRemoteInstallService;
import systems.hugmesh.adminbff.device.DeviceRegistryRepository;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

import java.util.Map;

/**
 * Wiring for the in-UI device SSH-terminal LIVE transport — config-only, mirroring
 * {@code WorkloadConsoleClientConfig}.
 *
 * <ul>
 *   <li>The transport is wired by ONE flag ({@code app.device-terminal.enabled}, default false)
 *       gating two MUTUALLY-EXCLUSIVE beans, mirroring the {@code DesktopSshClient} Noop/Rest idiom:
 *       <b>flag off (DEFAULT)</b> → the no-dial {@link StubDeviceSshTransport}
 *       ({@code @ConditionalOnProperty(havingValue="false", matchIfMissing=true)}) so the feature
 *       SHIPS DARK and NO real SSH happens; <b>flag on</b> → the REAL
 *       {@link SshDeviceTerminalTransport} (idle-timeout + max-sessions + real PTY lifecycle). The
 *       handler's 5 connect-time gates are UNCHANGED either way;</li>
 *   <li>even flag-on, the real transport dials through the {@link DeviceSshChannelFactory} seam,
 *       whose only shipped impl ({@link UnconfiguredDeviceSshChannelFactory},
 *       {@code @ConditionalOnMissingBean}) FAILS CLOSED — no SSH library + no device host-key source
 *       is a FLAGGED follow-on decision (see {@link DeviceSshChannelFactory}); a concrete factory
 *       overrides it once that decision lands;</li>
 *   <li>the handler is mounted at {@code /bff/admin/device-terminal/**} (HIGHEST_PRECEDENCE so it
 *       wins the path over the annotated controllers), which already sits under the coarse
 *       {@code /bff/admin/**} → {@code hasAnyRole('ADMIN','SUPERADMIN')} gate in
 *       {@code SecurityConfig} — so NO SecurityConfig change is required;</li>
 *   <li>{@link EnableConfigurationProperties} binds the {@code app.device-terminal.*} gate.</li>
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({DeviceTerminalProperties.class, DeviceTerminalDialProperties.class})
public class DeviceTerminalConfig {

    private static final Logger log = LoggerFactory.getLogger(DeviceTerminalConfig.class);

    /** Ships-dark DEFAULT transport — the no-dial stub. In force whenever
     *  {@code app.device-terminal.enabled} is false/absent, so a dev/test/CI run (and any
     *  deployment that has not opted in) reaches NO real device. Mutually exclusive with
     *  {@link #sshDeviceTerminalTransport} (the {@code havingValue} flips between them). */
    @Bean
    @ConditionalOnProperty(name = "app.device-terminal.enabled", havingValue = "false",
            matchIfMissing = true)
    DeviceSshTransport stubDeviceSshTransport() {
        log.info("[device-terminal] LIVE transport = StubDeviceSshTransport (ships dark, no SSH dialed)");
        return new StubDeviceSshTransport();
    }

    /** The REAL transport — wired ONLY when {@code app.device-terminal.enabled=true}. Owns the
     *  idle-timeout + max-sessions enforcement and the real PTY session lifecycle; it dials through
     *  the {@link DeviceSshChannelFactory} seam (which itself fails closed until a concrete
     *  host-key-verifying SSH factory lands — the FLAGGED decision). */
    @Bean
    @ConditionalOnProperty(name = "app.device-terminal.enabled", havingValue = "true")
    DeviceSshTransport sshDeviceTerminalTransport(DeviceSshChannelFactory channels,
                                                  DeviceTerminalProperties props) {
        log.info("[device-terminal] LIVE transport = SshDeviceTerminalTransport (idle-timeout={}, "
                + "max-sessions={}, channel canDial={})", props.getIdleTimeout(),
                props.getMaxSessions(), channels.canDial());
        return new SshDeviceTerminalTransport(channels, props);
    }

    /**
     * The REAL, host-key-PINNED sshj dial factory — the concrete {@link DeviceSshChannelFactory}
     * that the {@link UnconfiguredDeviceSshChannelFactory} was a placeholder for. Wired ONLY when
     * {@code app.device-terminal.dial.enabled=true} (the SECOND, independent ships-dark gate);
     * declared BEFORE the {@code @ConditionalOnMissingBean} unconfigured factory so, when the flag
     * is on, this concrete bean is registered first and the fail-closed default backs off.
     *
     * <p>Even with this bean wired, a connect is only possible when an ACTIVE {@code device_ssh_dial}
     * row exists for the device (the factory refuses otherwise) AND the presented host key matches
     * the pinned {@code host_key_fp} (no TOFU). The per-device dial PRIVATE key is read at dial time
     * from the ESO-synced K8s Secret mount and never logged/persisted. This is the bean that turns
     * {@link DeviceSshChannelFactory#canDial()} true — so enabling it requires a mandatory security
     * re-review.
     */
    @Bean
    @ConditionalOnProperty(name = "app.device-terminal.dial.enabled", havingValue = "true")
    DeviceSshChannelFactory sshjDeviceSshChannelFactory(DeviceSshDialRepository dials,
                                                        DeviceTerminalDialProperties dialProps) {
        log.warn("[device-terminal] channel factory = SshjDeviceSshChannelFactory (REAL DIAL, "
                + "host-key PINNED, no TOFU; dial key from ESO secret mount={}) — REQUIRES security "
                + "re-review before enablement", dialProps.getKeyMountPath());
        return new SshjDeviceSshChannelFactory(dials, dialProps);
    }

    /** The dial seam DEFAULT. FAILS CLOSED (never dials, never TOFU-trusts). In force whenever the
     *  concrete {@link #sshjDeviceSshChannelFactory} is NOT wired (i.e. {@code
     *  app.device-terminal.dial.enabled} is false/absent — the DEFAULT). {@link
     *  ConditionalOnMissingBean} so the concrete factory above transparently overrides it. */
    @Bean
    @ConditionalOnMissingBean(DeviceSshChannelFactory.class)
    DeviceSshChannelFactory unconfiguredDeviceSshChannelFactory() {
        log.warn("[device-terminal] channel factory = UnconfiguredDeviceSshChannelFactory "
                + "(fails closed — no SSH client / no device host-key source; FLAGGED decision)");
        return new UnconfiguredDeviceSshChannelFactory();
    }

    @Bean
    DeviceSshTerminalWebSocketHandler deviceSshTerminalWebSocketHandler(
            DesktopRemoteInstallService authz,
            DeviceRegistryRepository devices,
            DomainRegistry domainRegistry,
            WorkloadStepUpService stepUp,
            DeviceTerminalStepUpGate stepUpGate,
            systems.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp,
            DeviceSshTransport transport,
            DeviceTerminalProperties props,
            ObjectMapper mapper) {
        return new DeviceSshTerminalWebSocketHandler(
                authz, devices, domainRegistry, stepUp, stepUpGate, mfaStepUp, transport, props, mapper);
    }

    /**
     * Maps the terminal handshake at {@code /bff/admin/device-terminal/**} to the WS handler. The
     * handshake (an HTTP GET on the {@code /bff/admin/**} prefix) is gated by Spring Security's
     * {@code hasAnyRole('ADMIN','SUPERADMIN')}; the handler then enforces the own-domain
     * device-ssh-license re-check + step-up + flag at connect time before opening any transport.
     * HIGHEST_PRECEDENCE so it wins the path over the annotated controllers.
     */
    @Bean
    SimpleUrlHandlerMapping deviceTerminalWsHandlerMapping(DeviceSshTerminalWebSocketHandler handler) {
        Map<String, WebSocketHandler> map = Map.of("/bff/admin/device-terminal/**", handler);
        var mapping = new SimpleUrlHandlerMapping();
        mapping.setUrlMap(map);
        mapping.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return mapping;
    }

    /**
     * A {@link WebSocketHandlerAdapter} so the WebFlux dispatcher can invoke the handler. Guarded
     * by {@link ConditionalOnMissingBean} so it coexists with the workload-console adapter (only
     * one is needed app-wide; whichever registers first wins, the other is skipped).
     */
    @Bean
    @ConditionalOnMissingBean(WebSocketHandlerAdapter.class)
    WebSocketHandlerAdapter deviceTerminalWebSocketHandlerAdapter() {
        return new WebSocketHandlerAdapter();
    }
}
