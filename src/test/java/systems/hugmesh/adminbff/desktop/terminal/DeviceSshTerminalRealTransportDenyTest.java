package systems.hugmesh.adminbff.desktop.terminal;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.socket.CloseStatus;
import org.springframework.web.reactive.socket.HandshakeInfo;
import org.springframework.web.reactive.socket.WebSocketMessage;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import systems.hugmesh.adminbff.desktop.DesktopRemoteInstallService;
import systems.hugmesh.adminbff.desktop.DesktopRemoteInstallService.RemoteInstallDeniedException;
import systems.hugmesh.adminbff.device.Device;
import systems.hugmesh.adminbff.device.DeviceRegistryRepository;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Carries the #75 {@code verify(never()).open(...)} DENY list FORWARD against the REAL transport
 * bean: the handler is wired with a live {@link SshDeviceTerminalTransport} (backed by a MOCK
 * {@link DeviceSshChannelFactory} — no real device is ever dialed), and we assert that on EVERY
 * failed connect-time gate the channel factory's {@code open} is NEVER invoked, while the full
 * ALLOW path opens the PTY channel EXACTLY ONCE. This proves swapping the stub for the real
 * transport did not weaken the gate-before-open contract.
 */
class DeviceSshTerminalRealTransportDenyTest {

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
    private static final String BRANDX = "https://idp.brandx.example";
    private static final String DEVICE = "dev-1";
    private static final String OPERATOR = "admin-x";
    private static final String STEP_UP = "valid-step-up-token";

    private DesktopRemoteInstallService authz;
    private DeviceRegistryRepository devices;
    private WorkloadStepUpService stepUp;
    private DeviceSshChannelFactory factory; // the REAL transport's dial seam — MOCKED
    private DeviceSshChannelFactory.Channel channel;
    private DeviceTerminalProperties props;
    private DeviceSshTerminalWebSocketHandler handler;
    private CloseStatus closedWith;

    @BeforeEach
    void setUp() {
        authz = mock(DesktopRemoteInstallService.class);
        devices = mock(DeviceRegistryRepository.class);
        stepUp = mock(WorkloadStepUpService.class);
        factory = mock(DeviceSshChannelFactory.class);
        channel = mock(DeviceSshChannelFactory.Channel.class);
        props = new DeviceTerminalProperties();
        props.setEnabled(true); // flag ON so the REAL transport path runs.
        closedWith = null;

        // The REAL transport bean (not the stub), with idle-timeout disabled for determinism.
        DeviceSshTransport realTransport =
                new SshDeviceTerminalTransport(factory, Duration.ZERO, 16, Schedulers.parallel());
        assertThat(realTransport.isReal()).isTrue();

        // The step-up GATE is a REAL thin delegator over the workload step-up mock, so the token
        // leg behaves EXACTLY as before; the MFA leg ships DARK (isFresh -> false) so it never
        // satisfies and there is nothing to consume (byte-identical to today).
        DeviceTerminalStepUpGate stepUpGate = new DeviceTerminalStepUpGate(stepUp);
        systems.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp =
                mock(systems.hugmesh.authcore.casdoor.MfaStepUpService.class);
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());

        handler = new DeviceSshTerminalWebSocketHandler(
                authz, devices, REGISTRY, stepUp, stepUpGate, mfaStepUp, realTransport, props,
                new ObjectMapper());

        // ALLOW defaults; each DENY test breaks exactly one gate.
        when(stepUp.validate(eq(OPERATOR), eq(STEP_UP))).thenReturn(true);
        when(authz.authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.empty());
        when(devices.findById(eq(DEVICE)))
                .thenReturn(Mono.just(device(DEVICE, "brandx", "dev-1.mesh")));
        when(channel.output()).thenReturn(Flux.just("ok".getBytes()));
        when(factory.open(eq(DEVICE), anyString(), eq(OPERATOR), anyInt(), anyInt()))
                .thenReturn(Mono.just(channel));
        when(factory.canDial()).thenReturn(true);
    }

    // ── ALLOW twin: the REAL transport opens the channel EXACTLY ONCE ─────────────

    @Test
    void allow_full_opensRealChannelExactlyOnce_consumesStepUp() {
        run(BRANDX, OPERATOR, List.of("admin"), STEP_UP);
        verify(factory, times(1)).open(eq(DEVICE), eq("dev-1.mesh"), eq(OPERATOR), anyInt(), anyInt());
        verify(stepUp).consume(eq(OPERATOR));
    }

    // ── carried-forward DENY list — NONE may dial the channel ─────────────────────

    @Test
    void deny_missingStepUp_neverDials() {
        when(stepUp.validate(eq(OPERATOR), any())).thenReturn(false);
        run(BRANDX, OPERATOR, List.of("admin"), null);
        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        verify(factory, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
    }

    @Test
    void deny_noActiveLicense_neverDials() {
        when(authz.authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new RemoteInstallDeniedException("no active SSH license")));
        run(BRANDX, OPERATOR, List.of("admin"), STEP_UP);
        verify(factory, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
    }

    @Test
    void deny_crossDomain_neverDials() {
        when(authz.authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new RemoteInstallDeniedException("device is not in your domain")));
        run(BRANDX, OPERATOR, List.of("admin"), STEP_UP);
        verify(factory, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
    }

    @Test
    void deny_superadminOwnedNode_neverDials() {
        when(authz.authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new RemoteInstallDeniedException("SUPERADMIN-owned node")));
        run(BRANDX, OPERATOR, List.of("admin"), STEP_UP);
        verify(factory, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
    }

    @Test
    void deny_deviceNotRegistered_neverDials() {
        when(authz.authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new RemoteInstallDeniedException("not registered")));
        run(BRANDX, OPERATOR, List.of("admin"), STEP_UP);
        verify(factory, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
    }

    @Test
    void shipsDark_flagOff_neverDials_evenWithRealTransportBean() {
        props.setEnabled(false);
        run(BRANDX, OPERATOR, List.of("admin"), STEP_UP);
        // Gates still ran, but with the flag off the transport is never even invoked.
        verify(authz).authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class));
        verify(factory, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.NORMAL.getCode());
    }

    // ── harness ───────────────────────────────────────────────────────────────────

    private void run(String issuer, String subject, List<String> roles, String stepUpHeader) {
        WebSocketSession s = mockSession(issuer, stepUpHeader);
        JwtAuthenticationToken auth = jwtAuth(issuer, subject, roles);
        handler.handle(s).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)).block();
    }

    @SuppressWarnings("unchecked")
    private WebSocketSession mockSession(String issuer, String stepUpHeader) {
        WebSocketSession session = mock(WebSocketSession.class);
        HandshakeInfo info = mock(HandshakeInfo.class);
        when(info.getUri()).thenReturn(URI.create("ws://bff/bff/admin/device-terminal/" + DEVICE));
        HttpHeaders headers = new HttpHeaders();
        if (stepUpHeader != null) {
            headers.add(DeviceSshTerminalWebSocketHandler.STEP_UP_HEADER, stepUpHeader);
        }
        when(info.getHeaders()).thenReturn(headers);
        when(info.getPrincipal()).thenReturn(Mono.empty());
        when(session.getHandshakeInfo()).thenReturn(info);
        when(session.textMessage(anyString())).thenReturn(mock(WebSocketMessage.class));
        when(session.send(any())).thenAnswer(inv -> ((Flux<WebSocketMessage>) inv.getArgument(0)).then());
        when(session.receive()).thenReturn(Flux.empty());
        when(session.close(any(CloseStatus.class))).thenAnswer(inv -> {
            closedWith = inv.getArgument(0);
            return Mono.empty();
        });
        return session;
    }

    private static JwtAuthenticationToken jwtAuth(String issuer, String subject, List<String> roles) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .subject(subject).issuer(issuer).claim("roles", roles).build();
        List<SimpleGrantedAuthority> auths = roles.stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r.toUpperCase()))
                .toList();
        return new JwtAuthenticationToken(jwt, auths, subject);
    }

    private static Device device(String id, String domain, String hostname) {
        return new Device(id, "fp-" + id, hostname, "tn-1", Device.IMAGE_MESH_EXTENSION,
                "amd64-laptop", Device.OWNER_ADMIN, "owner-1", domain, "mesh-1",
                Instant.now(), Instant.now());
    }
}
