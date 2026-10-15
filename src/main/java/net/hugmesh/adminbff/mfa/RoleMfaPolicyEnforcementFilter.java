package net.hugmesh.adminbff.mfa;

import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.security.Roles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

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
 * Only {@code /bff/admin/**} and {@code /bff/superadmin/**}. Everything a principal needs in
 * order to GET fresh MFA stays reachable: {@code /bff/mfa/**} (enrol + challenge),
 * {@code /bff/login}, {@code /bff/session}, {@code /bff/sessionOut}, {@code /bff/me}, the
 * internal surface the gateway introspects through. Gating any of those would make the
 * requirement unsatisfiable.
 *
 * <h2>What counts as fresh MFA</h2>
 * Either of two pieces of evidence, whichever carrier the request arrived on:
 * <ul>
 *   <li>the {@code MFA_SATISFIED} authority — present only when {@code app.mfa.enabled} is on
 *       AND the JWT carries a fresh BFF-written {@code mfa_satisfied_at} claim (a JWT carrier);</li>
 *   <li>a fresh {@code bff_session} MFA stamp ({@link MfaStepUpService#isFresh}), read from the
 *       {@code bff_session} cookie or a {@code Bearer bff_...} header — the same lookup the
 *       step-up controllers perform. This is read-only: it never CONSUMES the stamp (the
 *       single-use consume belongs to the step-up gates, which still run on top).</li>
 * </ul>
 * <b>Carrier caveat.</b> A request that arrives as a custody JWT with {@code app.mfa.enabled}
 * off and no {@code bff_session} cookie carries neither piece of evidence, so it is denied for
 * a policy-required principal. Whoever turns this flag on must also have {@code app.mfa.enabled}
 * on (or have the cookie reach this service); that is an operator rollout step, not something
 * this class can decide.
 *
 * <h2>Domain</h2>
 * Taken from the validated issuer through {@link PrincipalDomain}, never from the request. A
 * non-JWT principal resolves to {@link PrincipalDomain#NO_DOMAIN}, which has no policy rows, so
 * only the built-in defaults (floor roles) apply to it.
 *
 * <h2>Not done here</h2>
 * No Casdoor property is cleared or stamped and no revocation row is written, so operator
 * decision 45 does not apply to this class. {@code methods} and {@code graceSeconds} are still
 * not honoured.
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

    static final List<String> GATED_PREFIXES = List.of("/bff/admin/", "/bff/superadmin/");

    private static final Logger log = LoggerFactory.getLogger(RoleMfaPolicyEnforcementFilter.class);

    private static final byte[] DENIED_BODY =
            ("{\"error\":\"multi-factor authentication is required for your role"
                    + " (complete an MFA challenge and retry)\"}").getBytes(StandardCharsets.UTF_8);

    private final RoleMfaPolicyService policies;
    private final MfaStepUpService mfaStepUp;
    private final DomainRegistry domainRegistry;

    public RoleMfaPolicyEnforcementFilter(RoleMfaPolicyService policies, MfaStepUpService mfaStepUp,
                                          DomainRegistry domainRegistry) {
        this.policies = policies;
        this.mfaStepUp = mfaStepUp;
        this.domainRegistry = domainRegistry;
        if (!mfaStepUp.enabled()) {
            log.warn("{}=true but app.casdoor.mfa.enabled=false: no session can carry an MFA stamp,"
                    + " so role-policy enforcement is INACTIVE (it would lock every privileged"
                    + " principal out)", FLAG);
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!mfaStepUp.enabled() || !gated(exchange.getRequest().getPath().value())) {
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

    static boolean gated(String path) {
        for (String prefix : GATED_PREFIXES) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        return false;
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
        boolean carriedEvidence = mfaAuthority;
        return policies.requiredForAny(domain, roles)
                .flatMap(required -> {
                    if (!required || carriedEvidence) {
                        return Mono.just(Boolean.TRUE);
                    }
                    String token = sessionToken(exchange);
                    return token == null
                            ? Mono.just(Boolean.FALSE)
                            : mfaStepUp.isFresh(token).map(fresh -> Boolean.TRUE.equals(fresh));
                });
    }

    private static String sessionToken(ServerWebExchange exchange) {
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(SessionCookieWebFilter.SESSION_COOKIE);
        return SessionCookieWebFilter.bffTokenFrom(cookie == null ? null : cookie.getValue(),
                exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
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
