package net.hugmesh.adminbff.mfa;

import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.account.BffSession;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.security.Roles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.RequestPath;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The first CALLER of {@link RoleMfaPolicyService#requiredForAny}: on the privileged admin
 * surface, a principal whose roles the per-(domain, role) policy says need MFA is refused with
 * 403 until it presents fresh MFA evidence.
 *
 * <h2>Dark by construction</h2>
 * The bean exists ONLY when {@value #FLAG} is {@code true}; the property is unset in
 * {@code application.yml} (so it defaults off) and no deploy manifest sets it. It is a NEW key,
 * deliberately NOT {@code app.casdoor.mfa.enabled}: that one is already {@code true} in the
 * cluster admin-bff Deployment and the local compose stack (hugmesh-generator
 * {@code specs/cluster/manifests/admin-bff-api/deployment.yaml}, {@code APP_CASDOOR_MFA_ENABLED}),
 * so riding it would turn the denial on at the first deploy after merge. With the flag off no
 * filter exists, so no request touches this class or the policy store.
 *
 * <p>The existing flag is still a PRECONDITION, not a substitute: when
 * {@link MfaStepUpService#enabled()} is {@code false} nothing can ever stamp a session, so
 * denying would lock every privileged principal out with no way to satisfy the check. In that
 * state the filter passes every request through (and says so once at startup).
 *
 * <h2>Where it denies, and where it must not</h2>
 * Only {@code /bff/admin/**} and {@code /bff/superadmin/**}, recognised on the decoded,
 * normalised path (see {@link #gated(RequestPath)}), not on the raw spelling. Everything a principal needs in
 * order to GET fresh MFA stays reachable: {@code /bff/mfa/**} (enrol + challenge),
 * {@code /bff/login}, {@code /bff/session}, {@code /bff/sessionOut}, {@code /bff/me}, the
 * internal surface the gateway introspects through. Gating any of those would make the
 * requirement unsatisfiable.
 *
 * <h2>What counts as fresh MFA</h2>
 * The policy answer is the MERGED {@link MfaRequirement} across the principal's roles
 * ({@link RoleMfaPolicyService#requirementFor}): required or not, the strictest grace window and
 * the intersection of the allowed methods. Against it, either of two pieces of evidence,
 * whichever carrier the request arrived on:
 * <ul>
 *   <li>the {@code MFA_SATISFIED} authority on a JWT principal — present only when
 *       {@code app.mfa.enabled} is on AND the JWT carries a fresh BFF-written
 *       {@code mfa_satisfied_at} claim (fresh by the gateway's own window). When a policy sets a
 *       POSITIVE grace, that claim is re-read here and must also be within the grace; when a
 *       policy restricts methods, the JWT's {@code amr} claim must name an allowed one (absent =
 *       denied). On a {@code bff_} session principal the same authority is granted from the raw
 *       {@code mfa_satisfied} flag with no freshness window, so there it is ignored and only the
 *       session check below counts;</li>
 *   <li>the MFA stamp on the principal's OWN {@code bff_session}
 *       ({@link AccountStore#sessionRow}): the token is the {@code Bearer bff_...} the
 *       principal was built from (a cookie-only request reaches this filter with the cookie
 *       already bridged into that header), never a {@code bff_session} cookie sent alongside a
 *       different Bearer, and the session must resolve to the account the principal names
 *       (see {@link #sessionEvidence}). The stamp passes only when {@code mfa_satisfied} is set,
 *       {@code mfa_satisfied_at} is younger than {@link MfaRequirement#window} and the stamped
 *       {@code amr} is allowed by {@link MfaRequirement#allowsMethod}. This is read-only: it
 *       never CONSUMES the stamp (the single-use consume belongs to the step-up gates, which
 *       still run on top).</li>
 * </ul>
 * <b>graceSeconds.</b> A policy's positive {@code graceSeconds} is the window its stamp must be
 * younger than; across several required roles the smallest wins. {@code 0} is the schema default
 * and the built-in default for every role: it means "no per-role grace of its own, re-prompt on
 * the platform cadence", i.e. the stamp must be fresh by {@link MfaStepUpService#freshness}
 * ({@code app.casdoor.mfa.freshness}, default 10m) — exactly what the filter enforced before
 * grace was honoured, so an existing row or an unseeded domain changes nothing. Reading
 * {@code 0} as "younger than 0 seconds" would deny the retry that follows a successful challenge
 * and lock every domain without rows out the moment the flag flips; the re-prompt itself is the
 * step-up gates' single-use consume, not this read-only check.
 * <p><b>Carrier caveat.</b> A principal authenticated by a custody JWT never has session evidence
 * here (a {@code bff_session} cookie sent with it replaces the JWT as the principal before this
 * filter runs), so it passes only with the {@code MFA_SATISFIED} authority. Whoever turns this
 * flag on must also have {@code app.mfa.enabled} on for JWT callers; that is an operator
 * rollout step, not something this class can decide.
 *
 * <h2>Domain</h2>
 * Taken from the validated issuer through {@link PrincipalDomain}, never from the request. A
 * non-JWT principal resolves to {@link PrincipalDomain#NO_DOMAIN}, which has no policy rows, so
 * only the built-in defaults (floor roles) apply to it.
 *
 * <h2>Not done here</h2>
 * No Casdoor property is cleared or stamped and no revocation row is written, so operator
 * decision 45 does not apply to this class. A stamp dated in the future is not rejected (the
 * stamp is the database's {@code now()}, the comparison is this JVM's clock; a skew guard would
 * need a tolerance nobody has measured).
 */
@Component
@ConditionalOnProperty(name = RoleMfaPolicyEnforcementFilter.FLAG, havingValue = "true")
@Order(RoleMfaPolicyEnforcementFilter.ORDER)
public class RoleMfaPolicyEnforcementFilter implements WebFilter {

    /** The default-off switch. */
    public static final String FLAG = "app.casdoor.mfa.role-policy.enforce";

    /**
     * Just AFTER Spring Security's WebFilterChainProxy ({@code -100}), so the authenticated
     * principal is already in the reactive security context when this runs.
     */
    public static final int ORDER = -90;

    /** Stable machine-readable signal on a denial. */
    public static final String SIGNAL_HEADER = "X-Mfa-Required";

    /** The two privileged surfaces: the segment directly under {@code /bff}, lower case. */
    static final Set<String> GATED_SEGMENTS = Set.of("admin", "superadmin");

    private static final int MAX_DECODE_ROUNDS = 4;

    private static final Logger log = LoggerFactory.getLogger(RoleMfaPolicyEnforcementFilter.class);

    private static final byte[] DENIED_BODY =
            ("{\"error\":\"multi-factor authentication is required for your role"
                    + " (complete an MFA challenge and retry)\"}").getBytes(StandardCharsets.UTF_8);

    private final RoleMfaPolicyService policies;
    private final MfaStepUpService mfaStepUp;
    private final DomainRegistry domainRegistry;
    private final ObjectProvider<AccountStore> accounts;

    public RoleMfaPolicyEnforcementFilter(RoleMfaPolicyService policies, MfaStepUpService mfaStepUp,
                                          DomainRegistry domainRegistry,
                                          ObjectProvider<AccountStore> accounts) {
        this.policies = policies;
        this.mfaStepUp = mfaStepUp;
        this.domainRegistry = domainRegistry;
        this.accounts = accounts;
        if (!mfaStepUp.enabled()) {
            log.warn("{}=true but app.casdoor.mfa.enabled=false: no session can carry an MFA stamp,"
                    + " so role-policy enforcement is INACTIVE (it would lock every privileged"
                    + " principal out)", FLAG);
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!mfaStepUp.enabled() || !gated(exchange.getRequest().getPath())) {
            return chain.filter(exchange);
        }
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .flatMap(auth -> decide(exchange, auth))
                // No authenticated principal: nothing to enforce here — the security chain's
                // own 401/403 stands.
                .defaultIfEmpty(Boolean.TRUE)
                .flatMap(allowed -> allowed ? chain.filter(exchange) : deny(exchange));
    }

    /**
     * Whether the request targets a gated surface, decided on the SAME decoded form the router
     * matches rather than on the raw wire spelling. The raw path is never prefix-tested: a
     * percent-encoded letter ({@code /bff/%61dmin/...}), a path parameter ({@code
     * /bff/admin;x=1/...}), dot segments or repeated slashes all route to the guarded
     * controllers while defeating a {@code startsWith} on the raw string.
     *
     * <p>The decision errs toward gating (fail CLOSED): segments are percent-decoded repeatedly
     * until stable, an encoded or literal separator ({@code /} or {@code \}) inside a segment
     * is treated as a separator, {@code .} / {@code ..} are resolved, empty segments are
     * dropped and the comparison ignores case. Only the segment that follows {@code /bff} is
     * compared, so {@code /bff/administrator} and {@code /bff/mfa/...} stay ungated.
     */
    static boolean gated(RequestPath path) {
        List<String> segments = normalisedSegments(path.pathWithinApplication());
        return segments.size() >= 2 && "bff".equalsIgnoreCase(segments.get(0))
                && GATED_SEGMENTS.contains(segments.get(1).toLowerCase(Locale.ROOT));
    }

    /** Convenience for a raw request path with no context path. */
    static boolean gated(String rawPath) {
        return gated(RequestPath.parse(rawPath, null));
    }

    static List<String> normalisedSegments(PathContainer path) {
        Deque<String> out = new ArrayDeque<>();
        for (PathContainer.Element element : path.elements()) {
            if (!(element instanceof PathContainer.PathSegment segment)) {
                continue;
            }
            // valueToMatch() is percent-decoded once and has any ;params removed, exactly as
            // the router sees it. Decode further so a double-encoded spelling cannot hide.
            String value = segment.valueToMatch();
            for (int i = 0; i < MAX_DECODE_ROUNDS && value.indexOf('%') >= 0; i++) {
                String next = decodeQuietly(value);
                if (next.equals(value)) {
                    break;
                }
                value = next;
            }
            for (String part : value.split("[/\\\\]", -1)) {
                int semi = part.indexOf(';');
                String name = semi >= 0 ? part.substring(0, semi) : part;
                if (name.isEmpty() || ".".equals(name)) {
                    continue;
                }
                if ("..".equals(name)) {
                    out.pollLast();
                    continue;
                }
                out.addLast(name);
            }
        }
        return List.copyOf(out);
    }

    private static String decodeQuietly(String value) {
        try {
            return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException malformed) {
            // Undecodable text cannot be a spelling of a gated name; compare it as it is.
            return value;
        }
    }

    /** {@code true} = let the request through. */
    private Mono<Boolean> decide(ServerWebExchange exchange, Authentication auth) {
        List<String> roles = new ArrayList<>();
        boolean mfaAuthority = false;
        for (GrantedAuthority ga : auth.getAuthorities()) {
            String a = ga.getAuthority();
            if (Roles.MFA_SATISFIED.equals(a)) {
                mfaAuthority = true;
            } else if (a != null && a.startsWith("ROLE_")) {
                roles.add(a);
            }
        }
        String domain = PrincipalDomain.of(auth, domainRegistry).domain();
        // The authority is FRESH evidence only on a JWT principal (the JWT converter grants it
        // from a freshness-checked claim). The bff_ session principal filter grants the same
        // authority from the raw mfa_satisfied flag with no freshness window, so for any other
        // principal it proves nothing here and the bound session check below decides.
        boolean carriedEvidence = mfaAuthority && auth instanceof JwtAuthenticationToken;
        return policies.requirementFor(domain, roles)
                // A lookup that yields nothing is an unknown answer: it must not read as "allow".
                .defaultIfEmpty(MfaRequirement.UNKNOWN)
                .flatMap(requirement -> {
                    if (!requirement.required()) {
                        return Mono.just(Boolean.TRUE);
                    }
                    if (carriedEvidence) {
                        return Mono.just(jwtEvidence(((JwtAuthenticationToken) auth).getToken(), requirement));
                    }
                    return sessionEvidence(exchange, auth, requirement);
                });
    }

    /**
     * The JWT path: the {@code MFA_SATISFIED} authority is the precondition (the converter
     * granted it from a claim fresh by the gateway's window). On top of it a POSITIVE per-role
     * grace re-reads {@code mfa_satisfied_at} and requires it within that grace, and a method
     * restriction requires the {@code amr} claim to name an allowed factor. A requirement with
     * neither tightening passes on the authority alone, exactly as before.
     */
    static boolean jwtEvidence(Jwt jwt, MfaRequirement requirement) {
        if (requirement.graceSeconds() > 0) {
            Long stampedAt = epochMillisClaim(jwt, Roles.MFA_SATISFIED_AT_CLAIM);
            if (stampedAt == null) {
                return false;
            }
            long ageMillis = System.currentTimeMillis() - stampedAt;
            if (ageMillis < 0 || ageMillis > requirement.graceSeconds() * 1000L) {
                return false;
            }
        }
        if (requirement.methodsConstrained()) {
            Object amr = jwt.getClaim("amr");
            if (amr instanceof Collection<?> many) {
                for (Object one : many) {
                    if (one != null && requirement.allowsMethod(one.toString())) {
                        return true;
                    }
                }
                return false;
            }
            return amr != null && requirement.allowsMethod(amr.toString());
        }
        return true;
    }

    private static Long epochMillisClaim(Jwt jwt, String name) {
        Object raw = jwt.getClaim(name);
        if (raw == null) {
            return null;
        }
        if (raw instanceof Number n) {
            return n.longValue() > 0 ? n.longValue() : null;
        }
        try {
            long ts = Long.parseLong(raw.toString().trim());
            return ts > 0 ? ts : null;
        } catch (NumberFormatException malformed) {
            return null;
        }
    }

    /**
     * MFA on the principal's OWN session that satisfies the requirement, or {@code false}. Two
     * independent bindings, so neither carrier precedence (decided in another library) nor a
     * second session riding on the request can lend a stamp:
     * <ol>
     *   <li>the token is read from the {@code Authorization} header the principal was built
     *       from (see {@link PrincipalSessionToken}), never from the {@code bff_session} cookie;</li>
     *   <li>that session row must name the account the principal names
     *       ({@link Authentication#getName()}); an unknown or expired session, a different
     *       account or a missing account store is a denial.</li>
     * </ol>
     * The row is read once ({@link AccountStore#sessionRow}) so the binding, the stamp, its time
     * and its method all come from the same session; the stamp itself is judged by
     * {@link #stampSatisfies}.
     */
    private Mono<Boolean> sessionEvidence(ServerWebExchange exchange, Authentication auth,
                                          MfaRequirement requirement) {
        String token = PrincipalSessionToken.fromAuthorization(exchange.getRequest().getHeaders());
        AccountStore store = accounts.getIfAvailable();
        String principal = auth.getName();
        if (token == null || store == null || principal == null) {
            return Mono.just(Boolean.FALSE);
        }
        Duration window = requirement.window(mfaStepUp.freshness());
        return store.sessionRow(token)
                .map(session -> principal.equals(session.accountId())
                        && stampSatisfies(session, requirement, window, LocalDateTime.now()))
                .defaultIfEmpty(Boolean.FALSE);
    }

    /**
     * Whether a session's MFA stamp satisfies the requirement: stamped, dated, younger than the
     * window (a stamp exactly {@code window} old still passes, as in
     * {@link MfaStepUpService#freshSnapshot}) and made with an allowed method. Fail closed on a
     * set flag with no timestamp (freshness cannot be proven) and on a constrained requirement
     * with a stamp that recorded no method.
     */
    static boolean stampSatisfies(BffSession session, MfaRequirement requirement, Duration window,
                                  LocalDateTime now) {
        if (session == null || !session.mfaSatisfied() || session.mfaSatisfiedAt() == null) {
            return false;
        }
        if (session.mfaSatisfiedAt().isBefore(now.minus(window))) {
            return false;
        }
        return requirement.allowsMethod(session.amr());
    }

    private static Mono<Void> deny(ServerWebExchange exchange) {
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().set(SIGNAL_HEADER, "true");
        DataBuffer buf = response.bufferFactory().wrap(DENIED_BODY);
        return response.writeWith(Mono.just(buf));
    }
}
