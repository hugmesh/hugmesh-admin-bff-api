package net.hugmesh.adminbff.desktop.terminal;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.socket.CloseStatus;
import org.springframework.web.reactive.socket.HandshakeInfo;
import org.springframework.web.reactive.socket.WebSocketMessage;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;
import net.hugmesh.adminbff.desktop.DesktopRemoteInstallService;
import net.hugmesh.adminbff.desktop.DesktopRemoteInstallService.RemoteInstallDeniedException;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

import java.net.URI;
import java.security.Principal;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The SECURITY HEART of the in-UI SSH-terminal LIVE transport: every connect-time gate of
 * {@link DeviceSshTerminalWebSocketHandler}, each DENY paired with {@code verify(transport,
 * never()).open(...)} and a fail-first-credible ALLOW twin that exercises the SAME path so the
 * never()-assertions cannot pass vacuously.
 *
 * <p>Threat model: cross-TIER + cross-domain. Domain comes from the validated JWT issuer (via
 * {@link PrincipalDomain}), never a param. The deep authz (own-domain wall + superadmin-owned-node
 * guard + license lookup) lives in {@code DesktopRemoteInstallService} and is unit-tested there;
 * here we mock that service and prove the handler (a) re-invokes it (never trusts the earlier
 * authorize REST call), (b) closes WITHOUT opening a transport on ANY failed gate, and (c) opens
 * the transport EXACTLY ONCE on the full ALLOW path.
 */
class DeviceSshTerminalWebSocketHandlerTest {

    // Multi-issuer registry so a real per-brand domain is derived from the validated issuer.
    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
    private static final String BRANDX = "https://idp.brandx.example";

    private static final String DEVICE = "dev-1";
    private static final String OPERATOR = "admin-x";
    private static final String STEP_UP = "valid-step-up-token";
    // The single, non-distinguishing client close reason for EVERY authorization/license denial.
    private static final String GENERIC_DENY_REASON =
            DeviceSshTerminalWebSocketHandler.GENERIC_DENY_REASON;

    private DesktopRemoteInstallService authz;
    private DeviceRegistryRepository devices;
    private WorkloadStepUpService stepUp;
    private DeviceTerminalStepUpGate stepUpGate;
    private net.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    private DeviceSshTransport transport;
    private DeviceSshTransport.Session ttySession;
    private DeviceTerminalProperties props;
    private DeviceSshTerminalWebSocketHandler handler;

    // capture of the close status the handler used.
    private CloseStatus closedWith;

    // Captures the handler's server-side audit log so the DENY tests can assert the SPECIFIC cause
    // is preserved server-side even though the client only ever sees the generic reason.
    private ListAppender<ILoggingEvent> auditAppender;
    private ch.qos.logback.classic.Logger handlerLogger;

    @BeforeEach
    void setUp() {
        authz = mock(DesktopRemoteInstallService.class);
        devices = mock(DeviceRegistryRepository.class);
        stepUp = mock(WorkloadStepUpService.class);
        // The step-up GATE is a REAL thin delegator over the workload step-up mock, so the existing
        // verify(stepUp).validate/consume assertions hold and the token leg is byte-identical.
        stepUpGate = new DeviceTerminalStepUpGate(stepUp);
        // A5 MFA leg ships DARK by default (isFresh -> false): the MFA leg never satisfies and
        // there is nothing to consume — the device-license + token gates run EXACTLY as today.
        // The fresh-MFA tests below override isFresh -> true and assert the license is STILL
        // enforced + the MFA stamp is consumed single-use.
        mfaStepUp = mock(net.hugmesh.authcore.casdoor.MfaStepUpService.class);
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        transport = mock(DeviceSshTransport.class);
        ttySession = mock(DeviceSshTransport.Session.class);
        props = new DeviceTerminalProperties();
        props.setEnabled(true); // flag ON for most tests; the dark proof flips it off.
        closedWith = null;

        handler = new DeviceSshTerminalWebSocketHandler(
                authz, devices, REGISTRY, stepUp, stepUpGate, mfaStepUp, transport, props,
                new ObjectMapper());

        // Attach a list appender to the handler's logger to verify the server-side audit path.
        LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
        handlerLogger = ctx.getLogger(DeviceSshTerminalWebSocketHandler.class);
        handlerLogger.setLevel(Level.INFO);
        auditAppender = new ListAppender<>();
        // Thread-safe, snapshot-iterating backing list: the handler runs a reactive WS
        // session that can emit a trailing audit log from an async thread, and under
        // class-level parallel execution a sibling instance shares this class logger —
        // either can append while auditLog() streams the list, racing a plain ArrayList
        // into ConcurrentModificationException. CopyOnWriteArrayList makes both safe.
        // (Same hardening as SshjDeviceSshChannelFactoryTest / AdminSshKeyIssuanceServiceTest.)
        auditAppender.list = new java.util.concurrent.CopyOnWriteArrayList<>();
        auditAppender.start();
        handlerLogger.addAppender(auditAppender);

        // Sensible ALLOW defaults; each DENY test overrides exactly one gate.
        when(stepUp.validate(eq(OPERATOR), eq(STEP_UP))).thenReturn(true);
        when(authz.authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.empty());
        when(devices.findById(eq(DEVICE))).thenReturn(Mono.just(device(DEVICE, "brandx", "dev-1.mesh")));
        when(ttySession.output()).thenReturn(Flux.just("hello".getBytes()));
        when(transport.open(eq(DEVICE), anyString(), eq(OPERATOR), anyInt(), anyInt()))
                .thenReturn(Mono.just(ttySession));
        when(transport.isReal()).thenReturn(false);
    }

    @AfterEach
    void tearDown() {
        if (handlerLogger != null && auditAppender != null) {
            handlerLogger.detachAppender(auditAppender);
            auditAppender.stop();
        }
    }

    /** The handler's server-side audit log lines captured this test. */
    private List<String> auditLog() {
        return auditAppender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    // ──────────────────────────── ALLOW twin ────────────────────────────────────

    @Test
    void allow_licensedAdmin_validStepUp_ownDomain_flagOn_opensTransportExactlyOnce() {
        run(session(BRANDX, OPERATOR, List.of("admin"), STEP_UP, null));

        verify(stepUp).validate(eq(OPERATOR), eq(STEP_UP));
        verify(authz).authorizeTerminal(eq(OPERATOR), eq(DEVICE), argThat(PrincipalDomain::scoped));
        verify(transport, times(1)).open(eq(DEVICE), eq("dev-1.mesh"), eq(OPERATOR), anyInt(), anyInt());
        // single-use step-up consumed only on a real open.
        verify(stepUp).consume(eq(OPERATOR));
    }

    @Test
    void allow_superadmin_isUnscoped_opensTransport() {
        when(stepUp.validate(eq("super-1"), eq(STEP_UP))).thenReturn(true);
        when(authz.authorizeTerminal(eq("super-1"), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.empty());
        when(transport.open(eq(DEVICE), anyString(), eq("super-1"), anyInt(), anyInt()))
                .thenReturn(Mono.just(ttySession));

        run(session(BRANDX, "super-1", List.of("superadmin"), STEP_UP, null));

        verify(authz).authorizeTerminal(eq("super-1"), eq(DEVICE),
                argThat(s -> !s.scoped())); // superadmin scope is unscoped
        verify(transport, times(1)).open(eq(DEVICE), anyString(), eq("super-1"), anyInt(), anyInt());
    }

    // ──────────────────────────── DENY gates ────────────────────────────────────

    @Test
    void deny_unauthenticated_noPrincipalInContext_closesAndNeverOpens() {
        // No security context at all → switchIfEmpty close.
        StepVerifierless(handler.handle(mockSession(BRANDX, STEP_UP, null)));
        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
    }

    @Test
    void deny_missingStepUp_closesAndNeverOpens() {
        when(stepUp.validate(eq(OPERATOR), any())).thenReturn(false);

        run(session(BRANDX, OPERATOR, List.of("admin"), null, null));

        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        verify(authz, never()).authorizeTerminal(anyString(), anyString(), any());
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
    }

    @Test
    void deny_invalidStepUp_closesAndNeverOpens() {
        when(stepUp.validate(eq(OPERATOR), eq("wrong"))).thenReturn(false);

        run(session(BRANDX, OPERATOR, List.of("admin"), "wrong", null));

        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
    }

    // SECURITY: every authorization/license denial below MUST close with the SAME generic,
    // non-distinguishing reason (the topology-disclosure defence). The client must not be able to
    // tell "no license" from "wrong domain" from "superadmin-owned" from "device not registered" —
    // otherwise a step-upped scoped ADMIN could enumerate cross-tenant device existence/residency.
    // The specific cause is asserted to survive SERVER-SIDE in the audit log (see the appender).

    @Test
    void deny_noActiveLicense_closesGenericNeverOpens_specificCauseAuditedServerSide() {
        when(authz.authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new RemoteInstallDeniedException(
                        "you hold no active SSH license for this device")));

        run(session(BRANDX, OPERATOR, List.of("admin"), STEP_UP, null));

        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        // Client sees ONLY the generic reason — never the distinct license message.
        assertThat(closedWith.getReason()).isEqualTo(GENERIC_DENY_REASON);
        assertThat(closedWith.getReason()).doesNotContain("license");
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
        // …but the specific cause IS preserved server-side for audit/forensics.
        assertThat(auditLog()).anySatisfy(m -> assertThat(m)
                .contains("DENY (audit)").contains(DEVICE)
                .contains("you hold no active SSH license for this device"));
    }

    @Test
    void deny_crossDomainAdmin_serviceDeniesNotInYourDomain_closesGenericNeverOpens() {
        // A brandx admin reaching a brandy-resident device: the service's own-domain wall denies.
        when(authz.authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new RemoteInstallDeniedException("device is not in your domain")));

        run(session(BRANDX, OPERATOR, List.of("admin"), STEP_UP, null));

        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        // Cross-domain residency must NOT leak: identical generic reason, no "domain" hint.
        assertThat(closedWith.getReason()).isEqualTo(GENERIC_DENY_REASON);
        assertThat(closedWith.getReason()).doesNotContain("domain");
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
        assertThat(auditLog()).anySatisfy(m -> assertThat(m)
                .contains("DENY (audit)").contains("device is not in your domain"));
    }

    @Test
    void deny_superadminOwnedNodeReachedByScopedAdmin_closesGenericNeverOpens() {
        when(authz.authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new RemoteInstallDeniedException(
                        "cannot open an SSH terminal onto a SUPERADMIN-owned node — superadmin "
                        + "reach is mesh-membership, not a license")));

        run(session(BRANDX, OPERATOR, List.of("admin"), STEP_UP, null));

        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        // Ownership-type (superadmin-owned) must NOT leak to a scoped admin.
        assertThat(closedWith.getReason()).isEqualTo(GENERIC_DENY_REASON);
        assertThat(closedWith.getReason()).doesNotContain("SUPERADMIN");
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
        assertThat(auditLog()).anySatisfy(m -> assertThat(m)
                .contains("DENY (audit)").contains("SUPERADMIN-owned node"));
    }

    @Test
    void deny_deviceNotRegistered_closesGenericNeverOpens() {
        // A probed deviceId that doesn't exist at all: must be indistinguishable from any other
        // denial so existence cannot be enumerated.
        when(authz.authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new RemoteInstallDeniedException(
                        "device " + DEVICE + " is not registered")));

        run(session(BRANDX, OPERATOR, List.of("admin"), STEP_UP, null));

        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        // Existence must NOT leak: identical generic reason, no "registered" hint.
        assertThat(closedWith.getReason()).isEqualTo(GENERIC_DENY_REASON);
        assertThat(closedWith.getReason()).doesNotContain("registered");
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
        assertThat(auditLog()).anySatisfy(m -> assertThat(m)
                .contains("DENY (audit)").contains("is not registered"));
    }

    @Test
    void deny_blankDeviceId_closesAndNeverOpens() {
        // Path with no device segment after /device-terminal/ .
        WebSocketSession s = mockSession("/bff/admin/device-terminal/", BRANDX, OPERATOR,
                List.of("admin"), STEP_UP, null);
        run0(s, BRANDX, OPERATOR, List.of("admin"));
        assertThat(closedWith).isNotNull();
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
    }

    // ──────────────────────── ships-dark proof ──────────────────────────────────

    @Test
    void shipsDark_flagOff_authorizesButNeverOpensTransport() {
        props.setEnabled(false); // the default — feature dark.

        run(session(BRANDX, OPERATOR, List.of("admin"), STEP_UP, null));

        // The license + step-up gates STILL ran (re-check is unconditional)…
        verify(stepUp).validate(eq(OPERATOR), eq(STEP_UP));
        verify(authz).authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class));
        // …but with the flag off NO transport is opened and the socket closes cleanly.
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.NORMAL.getCode());
    }

    @Test
    void shipsDark_stubTransport_isNotReal_andEmitsBanner() {
        DeviceSshTransport stub = new StubDeviceSshTransport();
        assertThat(stub.isReal()).isFalse();
        DeviceSshTransport.Session s = stub.open(DEVICE, "dev-1.mesh", OPERATOR, 80, 24).block();
        byte[] banner = s.output().blockFirst();
        assertThat(new String(banner)).contains("ships dark");
    }

    // ──────────────── A5 co-equal MFA step-up leg (U3) ───────────────────────────
    // The terminal dial gets a fresh-MFA satisfier (parity with the sibling DesktopRemoteInstall).
    // DARK is the default (mfaStepUp.isFresh -> false in setUp), so every test above is
    // byte-identical to today (only the workload-token leg satisfies). Below: a FRESH MFA stamp on
    // the bff_session cookie satisfies step-up with NO workload token, the device-ssh-license
    // re-check STILL runs and STILL denies when there is no license (never bypassed), and the MFA
    // stamp is consumed single-use only on a real open.

    @Test
    void freshMfa_viaBffCookie_noWorkloadToken_opensTransport_andConsumesBothLegs() {
        // No step-up header/subprotocol -> the workload-token leg is unsatisfied (validate(op,null)
        // returns false). A fresh MFA stamp on the bff_session cookie carries the step-up.
        when(stepUp.validate(eq(OPERATOR), any())).thenReturn(false); // token leg never satisfies
        when(mfaStepUp.isFresh(eq("bff_sess1"))).thenReturn(Mono.just(true));

        run0(mockSessionWithBffCookie(OPERATOR, List.of("admin"), "bff_sess1"),
                BRANDX, OPERATOR, List.of("admin"));

        // The device-ssh-license re-check STILL ran (MFA satisfies step-up only, never the license).
        verify(authz).authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class));
        verify(transport, times(1)).open(eq(DEVICE), eq("dev-1.mesh"), eq(OPERATOR), anyInt(), anyInt());
        // Single-use: BOTH legs consumed on the real open (workload token + the MFA freshness).
        verify(stepUp).consume(eq(OPERATOR));
        verify(mfaStepUp).consume(eq("bff_sess1"));
    }

    @Test
    void freshMfa_doesNotBypassDeviceLicense_closesGenericNeverOpens() {
        // A fresh MFA stamp satisfies STEP-UP, but the own-domain + active-device-ssh-license
        // re-check (authorizeTerminal) STILL runs and STILL denies — the MFA leg never bypasses it.
        when(stepUp.validate(eq(OPERATOR), any())).thenReturn(false);
        when(mfaStepUp.isFresh(eq("bff_sess1"))).thenReturn(Mono.just(true));
        when(authz.authorizeTerminal(eq(OPERATOR), eq(DEVICE), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new RemoteInstallDeniedException(
                        "you hold no active SSH license for this device")));

        run0(mockSessionWithBffCookie(OPERATOR, List.of("admin"), "bff_sess1"),
                BRANDX, OPERATOR, List.of("admin"));

        // The license denial closes with the SAME generic reason and opens NO transport, and the
        // MFA freshness is NOT consumed (consume happens only on a real open).
        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        assertThat(closedWith.getReason()).isEqualTo(GENERIC_DENY_REASON);
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
        verify(mfaStepUp, never()).consume(anyString());
        assertThat(auditLog()).anySatisfy(m -> assertThat(m)
                .contains("DENY (audit)").contains("you hold no active SSH license for this device"));
    }

    @Test
    void noWorkloadToken_andMfaDark_closesNeverOpens_byteIdenticalToToday() {
        // Ships-dark proof for U3: with the MFA flag off (isFresh -> false, the setUp default) and
        // NO workload token, step-up is unsatisfiable -> close, no transport, no license probe.
        when(stepUp.validate(eq(OPERATOR), any())).thenReturn(false);
        // mfaStepUp.isFresh -> false by default (dark).

        run0(mockSessionWithBffCookie(OPERATOR, List.of("admin"), "bff_sess1"),
                BRANDX, OPERATOR, List.of("admin"));

        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        verify(authz, never()).authorizeTerminal(anyString(), anyString(), any());
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
        verify(mfaStepUp, never()).consume(anyString());
    }

    // ──────────────── step-up CONTRACT: subprotocol smuggle, query path GONE ───────

    // The browser cannot set X-Device-Terminal-StepUp, so it smuggles the token in a
    // Sec-WebSocket-Protocol value prefixed with STEP_UP_SUBPROTOCOL_PREFIX. It is validated
    // IDENTICALLY (same WorkloadStepUpService.validate) and consumed single-use on a real open.

    @Test
    void stepUp_viaSubprotocol_isAccepted_opensTransport() {
        WebSocketSession s = mockSessionWithSubprotocolStepUp(BRANDX, OPERATOR, List.of("admin"), STEP_UP);
        run0(s, BRANDX, OPERATOR, List.of("admin"));

        verify(stepUp).validate(eq(OPERATOR), eq(STEP_UP));
        verify(transport, times(1)).open(eq(DEVICE), eq("dev-1.mesh"), eq(OPERATOR), anyInt(), anyInt());
        verify(stepUp).consume(eq(OPERATOR));
    }

    @Test
    void stepUp_header_stillWorks_forNonBrowserClients() {
        // The header path is retained for CLI/non-browser callers.
        run(session(BRANDX, OPERATOR, List.of("admin"), STEP_UP, null));
        verify(stepUp).validate(eq(OPERATOR), eq(STEP_UP));
        verify(transport, times(1)).open(eq(DEVICE), anyString(), eq(OPERATOR), anyInt(), anyInt());
    }

    @Test
    void stepUp_viaQueryStringOnly_isNoLongerAuthorized_closesNeverOpens() {
        // The removed ?stepUp= path: a token presented ONLY in the URL query must NOT authorize.
        // The handler resolves NO step-up token from a safe channel (header/subprotocol), so the
        // step-up gate is not satisfied (a null token is fail-closed) and the handler closes
        // without opening a transport.
        when(stepUp.validate(eq(OPERATOR), any())).thenAnswer(inv ->
                STEP_UP.equals(inv.getArgument(1))); // ONLY the real token validates; null/other don't

        // header = null, query = the token. The handler must IGNORE the query.
        run(session(BRANDX, OPERATOR, List.of("admin"), null, STEP_UP));

        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
        // The token from the query was NEVER passed to validate as a credential — the query is not a
        // step-up channel. (The gate fail-closes a null token, so validate is not reached at all.)
        verify(stepUp, never()).validate(eq(OPERATOR), eq(STEP_UP));
    }

    @Test
    void stepUp_blankSubprotocolToken_doesNotAuthorize() {
        when(stepUp.validate(eq(OPERATOR), any())).thenAnswer(inv -> STEP_UP.equals(inv.getArgument(1)));
        // A stepup. prefix with an empty token resolves to null → not authorized.
        WebSocketSession s = mockSessionWithSubprotocolStepUp(BRANDX, OPERATOR, List.of("admin"), "");
        run0(s, BRANDX, OPERATOR, List.of("admin"));

        assertThat(closedWith.getCode()).isEqualTo(CloseStatus.POLICY_VIOLATION.getCode());
        verify(transport, never()).open(anyString(), anyString(), anyString(), anyInt(), anyInt());
    }

    @Test
    void getSubProtocols_advertisesOnlyTheGenericSelector_notTheToken() {
        // The server echoes ONLY the generic selector (so the browser handshake completes); the
        // per-session stepup.<token> value is NEVER advertised/echoed.
        assertThat(handler.getSubProtocols())
                .containsExactly(DeviceSshTerminalWebSocketHandler.SELECTOR_SUBPROTOCOL);
        assertThat(handler.getSubProtocols().get(0))
                .doesNotStartWith(DeviceSshTerminalWebSocketHandler.STEP_UP_SUBPROTOCOL_PREFIX);
    }

    // ──────────────────────────── harness ───────────────────────────────────────

    /** A session whose step-up token rides a Sec-WebSocket-Protocol subprotocol value (browser
     *  path), alongside the generic selector — and NO step-up header and NO ?stepUp= query. */
    @SuppressWarnings("unchecked")
    private WebSocketSession mockSessionWithSubprotocolStepUp(String issuer, String subject,
                                                              List<String> roles, String token) {
        WebSocketSession session = mock(WebSocketSession.class);
        HandshakeInfo info = mock(HandshakeInfo.class);
        when(info.getUri()).thenReturn(URI.create("ws://bff/bff/admin/device-terminal/" + DEVICE));

        HttpHeaders headers = new HttpHeaders();
        // Browser offers: the generic selector + the smuggled token, comma-separated in one header.
        headers.add(DeviceSshTerminalWebSocketHandler.WS_PROTOCOL_HEADER,
                DeviceSshTerminalWebSocketHandler.SELECTOR_SUBPROTOCOL + ", "
                + DeviceSshTerminalWebSocketHandler.STEP_UP_SUBPROTOCOL_PREFIX + token);
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

    /** A session carrying ONLY the opaque {@code bff_session} handshake cookie (the browser MFA
     *  channel) and NO step-up header / NO subprotocol token — so step-up can be satisfied ONLY by
     *  the co-equal Casdoor-MFA leg (mfaStepUp.isFresh). Mirrors what a real browser handshake
     *  sends when the user has a fresh MFA stamp but no minted workload step-up token. */
    @SuppressWarnings("unchecked")
    private WebSocketSession mockSessionWithBffCookie(String subject, List<String> roles,
                                                      String bffSession) {
        WebSocketSession session = mock(WebSocketSession.class);
        HandshakeInfo info = mock(HandshakeInfo.class);
        when(info.getUri()).thenReturn(URI.create("ws://bff/bff/admin/device-terminal/" + DEVICE));
        when(info.getHeaders()).thenReturn(new HttpHeaders()); // no step-up header
        LinkedMultiValueMap<String, HttpCookie> cookies = new LinkedMultiValueMap<>();
        cookies.add("bff_session", new HttpCookie("bff_session", bffSession));
        when(info.getCookies()).thenReturn(cookies);
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

    /** Drive handle() with the authentication injected into the reactive context. */
    private void run(SessionWithAuth swa) {
        run0(swa.session, swa.issuer, swa.subject, swa.roles);
    }

    private void run0(WebSocketSession session, String issuer, String subject, List<String> roles) {
        JwtAuthenticationToken auth = jwtAuth(issuer, subject, roles);
        handler.handle(session)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                .block();
    }

    /** Drive handle() with NO authentication in the context (the unauthenticated DENY). */
    private void StepVerifierless(Mono<Void> mono) {
        mono.contextWrite(Context.empty()).block();
    }

    private record SessionWithAuth(WebSocketSession session, String issuer, String subject,
                                   List<String> roles) {
    }

    private SessionWithAuth session(String issuer, String subject, List<String> roles,
                                    String stepUpHeader, String stepUpQuery) {
        WebSocketSession s = mockSession("/bff/admin/device-terminal/" + DEVICE, issuer, subject,
                roles, stepUpHeader, stepUpQuery);
        return new SessionWithAuth(s, issuer, subject, roles);
    }

    private WebSocketSession mockSession(String issuer, String stepUpHeader, String stepUpQuery) {
        return mockSession("/bff/admin/device-terminal/" + DEVICE, issuer, OPERATOR,
                List.of("admin"), stepUpHeader, stepUpQuery);
    }

    @SuppressWarnings("unchecked")
    private WebSocketSession mockSession(String path, String issuer, String subject,
                                         List<String> roles, String stepUpHeader, String stepUpQuery) {
        WebSocketSession session = mock(WebSocketSession.class);
        HandshakeInfo info = mock(HandshakeInfo.class);

        StringBuilder uri = new StringBuilder("ws://bff" + path);
        if (stepUpQuery != null) uri.append("?stepUp=").append(stepUpQuery);
        when(info.getUri()).thenReturn(URI.create(uri.toString()));

        HttpHeaders headers = new HttpHeaders();
        if (stepUpHeader != null) {
            headers.add(DeviceSshTerminalWebSocketHandler.STEP_UP_HEADER, stepUpHeader);
        }
        when(info.getHeaders()).thenReturn(headers);
        when(info.getPrincipal()).thenReturn(Mono.empty()); // principal comes from the reactive ctx

        when(session.getHandshakeInfo()).thenReturn(info);
        when(session.textMessage(anyString())).thenReturn(mock(WebSocketMessage.class));
        // session.send drains the outbound flux; receive() yields nothing (client sends nothing).
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
