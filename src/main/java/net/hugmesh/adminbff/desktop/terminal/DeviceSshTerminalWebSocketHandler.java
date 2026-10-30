package net.hugmesh.adminbff.desktop.terminal;

import net.hugmesh.adminbff.mfa.PrincipalSessionToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.socket.CloseStatus;
import org.springframework.web.reactive.socket.WebSocketHandler;
import org.springframework.web.reactive.socket.WebSocketMessage;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.adminbff.desktop.DesktopRemoteInstallService;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.workload.WorkloadExecService;
import net.hugmesh.adminbff.workload.WorkloadStepUpService;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * The LIVE in-UI SSH-TERMINAL transport WebSocket handler (the missing piece the
 * {@code DesktopSshTerminalController} authorize endpoint was a scaffold for). Handshake path:
 * {@code /bff/admin/device-terminal/{deviceId}} (query {@code ?cols=&rows=}). Mirrors
 * {@code WorkloadExecWebSocketHandler}: an HTTP GET on the {@code /bff/admin/**} prefix, so the
 * coarse Spring Security gate ({@code hasAnyRole('ADMIN','SUPERADMIN')}) refuses an upgrade by a
 * MOD/USER/anonymous caller before this handler ever runs.
 *
 * <h3>Connect-time gates — ALL enforced HERE, BEFORE any transport is opened</h3>
 * On {@link #handle} the handler re-derives and re-checks everything (it NEVER trusts the earlier
 * {@code authorizeTerminal} REST call):
 * <ol>
 *   <li><b>Authenticated principal</b> — the reactive security context must carry an
 *       authenticated {@link Jwt}; otherwise close {@link CloseStatus#POLICY_VIOLATION}.</li>
 *   <li><b>Domain from the validated issuer</b> — the {@link PrincipalDomain} is resolved from the
 *       cryptographically-validated token ({@code iss} → {@code DOMAIN_<x>}), NEVER from a
 *       body/param. Fail-closed to the {@code NO_DOMAIN} sentinel.</li>
 *   <li><b>Active own-domain device-ssh-license re-check</b> — delegated to
 *       {@link DesktopRemoteInstallService#authorizeTerminal} (own-domain wall +
 *       SUPERADMIN-owned-node guard + active device-OR-domain license). A scoped ADMIN is denied
 *       for a cross-domain or a superadmin-owned device; a caller with no active license is denied.
 *       Any denial closes the socket and NEVER opens a transport.</li>
 *   <li><b>Step-up</b> — SSH-via-UI is a step-up-gated operation; the handshake must carry a
 *       currently-valid step-up token (reusing {@link WorkloadStepUpService}, the same broker the
 *       workload-exec danger tier uses) bound to the caller's subject. No valid step-up → close
 *       {@link CloseStatus#POLICY_VIOLATION}, no transport.</li>
 *   <li><b>Feature flag</b> — even past every gate, the LIVE transport only opens when
 *       {@code app.device-terminal.enabled=true}. Off (the default) → a clean close, no transport.
 *       And the DEFAULT transport bean is the no-dial {@link StubDeviceSshTransport}, so a
 *       flag-on dev/test deployment still reaches no real device.</li>
 * </ol>
 *
 * <h3>Protocol (xterm.js attach addon style — identical to workload-exec)</h3>
 * Inbound text frames are JSON {@code {"type":"stdin","data":"..."}} /
 * {@code {"type":"resize","cols":N,"rows":N}}; outbound frames carry the shell's stdout/stderr.
 *
 * <h3>Session record — the workload console's signed hash chain (decision 104 = B)</h3>
 * Operator answer of 2026-09-23 to D1 on hugmesh-admin-bff-api#11. EVERY stdin chunk (before it is
 * written to the device) and EVERY output chunk (before it is sent to the browser) is appended to a
 * {@link WorkloadExecService.Transcript} — the SAME signed, hash-chained, append-only log the
 * workload console's TTY writes ({@code WorkloadExecWebSocketHandler}), in the SAME v1 format:
 * sequence, session, actor, time, direction, the previous entry's hash and a hash of the chunk.
 * The chunk BYTES are never recorded — only their hash — so the record proves a session's shape
 * (when, how much, in which direction, in which order, by whom) and can verify a copy of the
 * transcript kept elsewhere, but cannot show what was typed or shown. Resize frames carry no
 * content and are not recorded, exactly as on the workload console. The session id is
 * {@code device-terminal/<deviceId>/<uuid>} so the chain names the device without changing the
 * canonical entry format.
 */
public class DeviceSshTerminalWebSocketHandler implements WebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(DeviceSshTerminalWebSocketHandler.class);

    /** Handshake header carrying the step-up token — for NON-BROWSER clients (CLI/tests) that can
     *  set arbitrary headers (mirrors {@code X-Workload-StepUp}). PUBLIC so the ONE terminal+install
     *  trust surface ({@link net.hugmesh.adminbff.desktop.terminal.DeviceTerminalStepUpGate},
     *  the remote-install controller, and the step-up mint contract) all reference the SAME constant
     *  — deliberately NOT a second {@code X-Desktop-StepUp} header. */
    public static final String STEP_UP_HEADER = "X-Device-Terminal-StepUp";

    /**
     * The BROWSER step-up channel. A browser {@code WebSocket} cannot set arbitrary request headers,
     * but it CAN send {@code Sec-WebSocket-Protocol} subprotocol values (the standard token-smuggle
     * the k8s dashboard / kubectl-exec-over-ws use). The browser sends two subprotocol values:
     * <pre>  new WebSocket(url, ["hugmesh.device-terminal", "hugmesh.device-terminal.stepup.&lt;TOKEN&gt;"])</pre>
     * and the handler reads the token off the {@code stepup.} value. This REPLACES the old
     * {@code ?stepUp=} query fallback (a token-in-URL leak: query strings land in proxy/access logs
     * and browser history). The query path is GONE — a token presented only via {@code ?stepUp=}
     * no longer authorizes.
     *
     * <p>Validated IDENTICALLY (same {@link WorkloadStepUpService#validate}) and consumed single-use
     * only on a real open, exactly as the header path. No UI consumes this yet, so changing the
     * contract now is free.
     */
    static final String STEP_UP_SUBPROTOCOL_PREFIX = "hugmesh.device-terminal.stepup.";
    /** The generic selector subprotocol the server ECHOES so the browser handshake completes
     *  (RFC 6455: a server should select one offered subprotocol). The per-session
     *  {@code stepup.<token>} value is offered ALONGSIDE this but is NEVER advertised/echoed (it is
     *  read off the request header), so the token does not become part of the negotiated protocol. */
    static final String SELECTOR_SUBPROTOCOL = "hugmesh.device-terminal";
    static final String WS_PROTOCOL_HEADER = "Sec-WebSocket-Protocol";
    static final String ROUTE_SEGMENT = "/device-terminal/";

    /**
     * The PUBLIC full live WS handshake-path PREFIX ({@code /bff/admin/device-terminal/}) — the
     * single source of truth for the path the {@code DesktopSshTerminalController} descriptor emits
     * and the test pins, so the UI/BFF contract cannot drift from where this handler is actually
     * mounted ({@code DeviceTerminalConfig} maps {@code /bff/admin/device-terminal/**} to it). A
     * caller appends the (authorized) deviceId to form {@code .../device-terminal/{deviceId}}.
     */
    public static final String WS_PATH_PREFIX = "/bff/admin" + ROUTE_SEGMENT;

    /**
     * The SINGLE, non-distinguishing close reason for EVERY authorization/license denial
     * (device-not-registered / cross-domain / SUPERADMIN-owned-node / no-active-license, AND the
     * post-authorize domain/device-resolution failure). Collapsing them is a deliberate
     * topology-disclosure defence: these gates run BEFORE the feature flag, so a step-upped scoped
     * ADMIN must NOT be able to tell the cases apart by the WS close frame and thereby enumerate a
     * foreign device's existence / residency-domain / ownership-type across tenants (cross-domain
     * isolation is the product's core threat model). The specific cause is preserved SERVER-SIDE in
     * the audit log only — see {@link #denyAuthorization}.
     */
    static final String GENERIC_DENY_REASON = "not authorized";

    private final DesktopRemoteInstallService authz;
    private final DeviceRegistryRepository devices;
    private final DomainRegistry domainRegistry;
    private final WorkloadStepUpService stepUp;
    private final DeviceTerminalStepUpGate stepUpGate;
    private final MfaStepUpService mfaStepUp;
    private final DeviceSshTransport transport;
    private final DeviceTerminalProperties props;
    private final ObjectMapper mapper;
    private final WorkloadExecService transcripts;

    public DeviceSshTerminalWebSocketHandler(DesktopRemoteInstallService authz,
                                             DeviceRegistryRepository devices,
                                             DomainRegistry domainRegistry,
                                             WorkloadStepUpService stepUp,
                                             DeviceTerminalStepUpGate stepUpGate,
                                             MfaStepUpService mfaStepUp,
                                             DeviceSshTransport transport,
                                             DeviceTerminalProperties props,
                                             ObjectMapper mapper,
                                             WorkloadExecService transcripts) {
        this.authz = authz;
        this.devices = devices;
        this.domainRegistry = domainRegistry;
        this.stepUp = stepUp;
        this.stepUpGate = stepUpGate;
        this.mfaStepUp = mfaStepUp;
        this.transport = transport;
        this.props = props;
        this.mapper = mapper;
        this.transcripts = transcripts;
    }

    /** Advertise ONLY the generic selector so the server echoes it and the browser handshake
     *  completes; the per-session {@code stepup.<token>} subprotocol is deliberately NOT listed
     *  (it must not be negotiated/echoed — it is read off the request header). */
    @Override
    public java.util.List<String> getSubProtocols() {
        return java.util.List.of(SELECTOR_SUBPROTOCOL);
    }

    @Override
    public Mono<Void> handle(WebSocketSession session) {
        String deviceId = deviceIdFrom(session.getHandshakeInfo().getUri().getPath());
        if (deviceId == null || deviceId.isBlank()) {
            return close(session, CloseStatus.BAD_DATA, "no deviceId in path", null, deviceId);
        }
        var query = parseQuery(session.getHandshakeInfo().getUri().getQuery());
        int cols = parseInt(query.get("cols"), 80);
        int rows = parseInt(query.get("rows"), 24);
        // Step-up: header (non-browser) OR Sec-WebSocket-Protocol subprotocol smuggle (browser).
        // The old ?stepUp= query fallback is REMOVED (token-in-URL leak) — query is NOT consulted.
        String stepUpToken = stepUpTokenFrom(session);
        // The caller's opaque bff_ session, read from the SAME safe channels the HTTP controllers
        // use — the bff_session handshake COOKIE (browser) or the Authorization handshake header
        // (CLI). NEVER a query/path field. Feeds the co-equal Casdoor-MFA step-up leg.
        String sessionToken = sessionTokenFrom(session);

        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                // (1) no security context / no authenticated principal → fail closed. Guarding the
                //     context lookup itself (NOT the whole chain) keeps a normal empty completion of
                //     a real session from being mistaken for "no principal".
                .switchIfEmpty(close(session, CloseStatus.POLICY_VIOLATION,
                        "no authenticated principal", null, deviceId).then(Mono.empty()))
                .flatMap(auth -> connectGated(session, auth, deviceId, stepUpToken, sessionToken, cols, rows))
                .onErrorResume(e -> {
                    log.warn("[device-terminal] connect error device={}: {}", deviceId, e.toString());
                    return close(session, CloseStatus.SERVER_ERROR, "connect error", null, deviceId);
                });
    }

    private Mono<Void> connectGated(WebSocketSession session, Authentication auth, String deviceId,
                                    String stepUpToken, String sessionToken, int cols, int rows) {
        // (1) authenticated principal carrying a validated JWT.
        if (auth == null || !auth.isAuthenticated() || !(auth.getPrincipal() instanceof Jwt jwt)) {
            return close(session, CloseStatus.POLICY_VIOLATION, "unauthenticated", auth, deviceId);
        }
        String operator = jwt.getSubject();
        if (operator == null || operator.isBlank()) {
            return close(session, CloseStatus.POLICY_VIOLATION, "no subject on token", auth, deviceId);
        }
        // (2) domain from the cryptographically-validated issuer (NEVER a body/param).
        PrincipalDomain scope = PrincipalDomain.of(auth, domainRegistry);

        // (4) A5 UNIFIED step-up: SSH-via-UI is step-up-gated. Satisfied by EITHER a valid workload
        //     step-up token OR a FRESH Casdoor-MFA stamp on the caller's opaque session — parity
        //     with the sibling DesktopRemoteInstall trigger via DeviceTerminalStepUpGate's 3-arg
        //     overload. The device-ssh-license + own-domain + role checks STAY (gate 3 below); the
        //     MFA leg (license-INDEPENDENT) satisfies ONLY the step-up re-confirmation and NEVER
        //     bypasses the license. Checked BEFORE the license probe so a missing step-up never
        //     reaches the registry. mfaStepUp.isFresh() is flag-gated + fail-closed
        //     (app.casdoor.mfa.enabled=false by default -> only the token leg works). Both legs are
        //     consumed single-use only on a real open (replay-proof).
        // Gate on MFA freshness then enforce step-up and re-verify device authorization.
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> handleStepUpAndAuthorize(session, auth, operator, deviceId,
                        stepUpToken, sessionToken, mfaFresh, scope, cols, rows));
    }

    /** Check the step-up gate then re-verify device authorization before opening the transport. */
    private Mono<Void> handleStepUpAndAuthorize(WebSocketSession session, Authentication auth,
                                                 String operator, String deviceId,
                                                 String stepUpToken, String sessionToken,
                                                 boolean mfaFresh, PrincipalDomain scope,
                                                 int cols, int rows) {
        if (!stepUpGate.isSatisfied(operator, stepUpToken, mfaFresh)) {
            return close(session, CloseStatus.POLICY_VIOLATION, "missing/invalid step-up", auth, deviceId);
        }
        // (3) RE-VERIFY (do not trust the earlier authorize REST call): own-domain wall +
        //     SUPERADMIN-owned-node guard + active device-ssh-license.
        return authz.authorizeTerminal(operator, deviceId, scope)
                .then(Mono.defer(() -> afterAuthorized(session, auth, operator, deviceId,
                        sessionToken, mfaFresh, cols, rows)))
                .onErrorResume(DesktopRemoteInstallService.RemoteInstallDeniedException.class, e ->
                        // Collapse EVERY distinct denial to the SAME generic client reason.
                        denyAuthorization(session, auth, operator, deviceId, e.getMessage()));
    }

    private Mono<Void> afterAuthorized(WebSocketSession session, Authentication auth, String operator,
                                       String deviceId, String sessionToken, boolean mfaFresh,
                                       int cols, int rows) {
        // (5) feature flag — even fully authorized, the LIVE transport only opens when enabled.
        //     Off (default) → clean close, NO transport opened (ships-dark proof).
        if (!props.isEnabled()) {
            log.info("[device-terminal] gate OFF — authorized but transport not opened (ships dark) "
                    + "device={} operator={}", deviceId, operator);
            return close(session, CloseStatus.NORMAL,
                    "device terminal disabled (ships dark)", auth, deviceId);
        }
        // Resolve the device row for the transport's hostname. authorizeTerminal already proved it
        // exists + is reachable by this operator; an empty here is a fail-closed close.
        return devices.findById(deviceId)
                // A row that authorizeTerminal just proved reachable but findById can't load is a
                // fail-closed denial; collapse it to the SAME generic reason (it must not be
                // distinguishable from any other authorization/license denial), audited server-side.
                .switchIfEmpty(denyAuthorization(session, auth, operator, deviceId,
                        "device row not resolvable after authorize").then(Mono.empty()))
                .flatMap(device -> openTransport(session, operator, device, sessionToken, mfaFresh,
                        cols, rows));
    }

    private Mono<Void> openTransport(WebSocketSession session, String operator, Device device,
                                     String sessionToken, boolean mfaFresh, int cols, int rows) {
        // Single-use step-up: consume BOTH legs now that we are committing to a real open
        // (replay-proof). The workload-token leg is always consumed (no-op if a token was not the
        // satisfier); the Casdoor-MFA freshness is consumed only when the MFA leg satisfied, so a
        // second privileged dial needs a fresh MFA challenge. Mirrors DesktopRemoteInstall.
        stepUp.consume(operator);
        if (mfaFresh) {
            mfaStepUp.consume(sessionToken).subscribe();
        }
        String transcriptSession = "device-terminal/" + device.id() + "/" + UUID.randomUUID();
        log.info("[device-terminal] AUTHORIZED + transport opening device={} operator={} real={}"
                + " transcript={}", device.id(), operator, transport.isReal(), transcriptSession);
        return transport.open(device.id(), device.hostname(), operator, cols, rows)
                .flatMap(tty -> bridge(session, tty, transcriptSession, operator));
    }

    /**
     * Pipe an OPENED device session to the WS session, recording both directions (decision 104).
     * One chain per opened session: created only once a transport exists, so a refused/failed open
     * records nothing beyond the audit lines.
     */
    private Mono<Void> bridge(WebSocketSession session, DeviceSshTransport.Session tty,
                              String transcriptSession, String operator) {
        WorkloadExecService.Transcript transcript =
                transcripts.newTranscript(transcriptSession, operator);
        Flux<WebSocketMessage> out = tty.output()
                .doOnNext(bytes -> transcript.append("out", bytes))
                .map(bytes -> session.textMessage(new String(bytes, StandardCharsets.UTF_8)));
        Mono<Void> in = session.receive()
                .doOnNext(msg -> handleInbound(msg, tty, transcript))
                .doFinally(sig -> tty.close())
                .then();
        return Mono.zip(session.send(out), in).then();
    }

    private void handleInbound(WebSocketMessage msg, DeviceSshTransport.Session tty,
                               WorkloadExecService.Transcript transcript) {
        try {
            JsonNode node = mapper.readTree(msg.getPayloadAsText());
            String type = node.path("type").asText("stdin");
            if ("resize".equals(type)) {
                tty.resize(node.path("cols").asInt(80), node.path("rows").asInt(24));
            } else {
                byte[] data = node.path("data").asText("").getBytes(StandardCharsets.UTF_8);
                // Recorded BEFORE it reaches the device (hash only, never the bytes).
                transcript.append("in", data);
                tty.writeStdin(data);
            }
        } catch (Exception e) {
            log.debug("[device-terminal] bad inbound frame: {}", e.toString());
        }
    }

    /**
     * Deny on an authorization/license failure: PRESERVE the specific cause SERVER-SIDE (WARN audit
     * line with subject + deviceId + the distinct reason for forensics), then close the socket with
     * the SINGLE {@link #GENERIC_DENY_REASON} so the client cannot tell the denial cases apart and
     * thereby enumerate cross-tenant device topology. NEVER opens a transport.
     */
    private Mono<Void> denyAuthorization(WebSocketSession session, Authentication auth, String operator,
                                         String deviceId, String specificCause) {
        return Mono.defer(() -> {
            log.warn("[device-terminal] DENY (audit) operator={} device={} cause={}",
                    operator, deviceId, specificCause);
            return close(session, CloseStatus.POLICY_VIOLATION, GENERIC_DENY_REASON, auth, deviceId);
        });
    }

    /** Close the socket with {@code status}+{@code reason} and an audit log, opening NO transport.
     *  Deferred so the audit log + {@code session.close} fire only when this Mono is actually
     *  subscribed (e.g. as a {@code switchIfEmpty} fallback), never eagerly at assembly time. */
    private Mono<Void> close(WebSocketSession session, CloseStatus status, String reason,
                             Authentication auth, String deviceId) {
        return Mono.defer(() -> {
            String actor = auth == null ? "anonymous" : auth.getName();
            log.info("[device-terminal] CLOSE device={} actor={} status={} reason={}",
                    deviceId, actor, status.getCode(), reason);
            return session.close(status.withReason(reason));
        });
    }

    static String deviceIdFrom(String path) {
        if (path == null) return null;
        int i = path.indexOf(ROUTE_SEGMENT);
        if (i < 0) return null;
        String tail = path.substring(i + ROUTE_SEGMENT.length());
        int slash = tail.indexOf('/');
        if (slash >= 0) tail = tail.substring(0, slash);
        return decode(tail);
    }

    /**
     * Resolve the step-up token from a SAFE channel only: the {@link #STEP_UP_HEADER} (non-browser
     * clients) OR a {@link #STEP_UP_SUBPROTOCOL_PREFIX}-prefixed {@code Sec-WebSocket-Protocol}
     * subprotocol value (browser). The {@code ?stepUp=} URL query is DELIBERATELY NOT consulted
     * (token-in-URL leak). Header wins if both are present; both feed the SAME
     * {@link WorkloadStepUpService#validate}.
     */
    private static String stepUpTokenFrom(WebSocketSession session) {
        var headers = session.getHandshakeInfo().getHeaders();
        String header = headers.getFirst(STEP_UP_HEADER);
        if (header != null && !header.isBlank()) {
            return header;
        }
        // Browser: Sec-WebSocket-Protocol carries a comma-separated list; pull the token off the
        // value prefixed with STEP_UP_SUBPROTOCOL_PREFIX. (HttpHeaders splits multi-values for us.)
        for (String raw : headers.getOrDefault(WS_PROTOCOL_HEADER, java.util.List.of())) {
            if (raw == null) continue;
            for (String proto : raw.split(",")) {
                String p = proto.trim();
                if (p.startsWith(STEP_UP_SUBPROTOCOL_PREFIX)) {
                    String token = p.substring(STEP_UP_SUBPROTOCOL_PREFIX.length());
                    return token.isBlank() ? null : token;
                }
            }
        }
        return null;
    }

    /**
     * Resolve the caller's opaque bff_ session token from the WS handshake — the SAME value the
     * HTTP controllers obtain via {@link PrincipalSessionToken#of(String, String)}, read
     * from SAFE channels only: the {@code Authorization} handshake header the principal was built
     * from (an explicit {@code Bearer bff_...}, or the cookie the session bridge copied there),
     * else the {@code bff_session} handshake COOKIE. Never a second session's cookie riding next
     * to a different Bearer. NEVER a query/path field. Returns
     * null when neither is present (then the Casdoor-MFA leg is simply unsatisfiable — fail-closed,
     * exactly the ships-dark behaviour). Null-guards {@code getCookies()} (it may be absent).
     */
    private static String sessionTokenFrom(WebSocketSession session) {
        var info = session.getHandshakeInfo();
        MultiValueMap<String, HttpCookie> cookies = info.getCookies();
        String sessionCookie = null;
        if (cookies != null) {
            HttpCookie c = cookies.getFirst(SessionCookieWebFilter.SESSION_COOKIE);
            if (c != null) {
                sessionCookie = c.getValue();
            }
        }
        HttpHeaders headers = info.getHeaders();
        String authHeader = headers == null ? null : headers.getFirst(HttpHeaders.AUTHORIZATION);
        return PrincipalSessionToken.of(sessionCookie, authHeader);
    }

    private static int parseInt(String v, int def) {
        try {
            return v == null ? def : Integer.parseInt(v);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static java.util.Map<String, String> parseQuery(String q) {
        java.util.Map<String, String> out = new java.util.LinkedHashMap<>();
        if (q == null || q.isBlank()) return out;
        for (String pair : q.split("&")) {
            int i = pair.indexOf('=');
            if (i > 0) {
                out.put(decode(pair.substring(0, i)), decode(pair.substring(i + 1)));
            }
        }
        return out;
    }

    private static String decode(String s) {
        try {
            return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }
}
