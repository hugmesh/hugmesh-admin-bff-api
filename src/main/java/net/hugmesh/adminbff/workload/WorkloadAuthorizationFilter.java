package net.hugmesh.adminbff.workload;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.commons.security.RoleName;

import java.util.List;

/**
 * The MANDATORY central WORKLOAD CONSOLE authorization predicate — a {@link WebFilter} on
 * {@code /bff/{admin,superadmin}/workloads/**} so NO console controller is reachable without
 * it (the spec's "no controller reachable without it"). It runs AFTER Spring Security's
 * authentication filter (so the {@link Authentication} is in the reactive context) and:
 *
 * <ol>
 *   <li>short-circuits with a 404 when the generator gate is OFF (the whole prefix does not
 *       exist — three independent OFFs: this gate, the DB master flag, an active grant);</li>
 *   <li>classifies the path+method into a {@link DangerTier} (NEVER the verb) +
 *       {@code logPath} via {@link WorkloadPathClassifier};</li>
 *   <li>runs the STEP-0b namespace allowlist BEFORE any controller/k8s call (an out-of-allowlist
 *       {@code ns} is a 403 + probe audit);</li>
 *   <li>delegates the STEP 0..6 decision to {@link WorkloadAuthorizationService};</li>
 *   <li>on DENY emits a 404 (no-existence-leak paths) or 403 (explicit refusals), recording the
 *       audit; on ALLOW lets the request through (the controller still applies STEP-7
 *       owner-chain attribution).</li>
 * </ol>
 *
 * <p>Ordered LATE (after the security webfilter, which sits at
 * {@code SecurityWebFiltersOrder.AUTHORIZATION}) so authentication has populated the context.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class WorkloadAuthorizationFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(WorkloadAuthorizationFilter.class);

    /**
     * All collaborators are injected as {@link ObjectProvider}s so the filter degrades
     * gracefully when wired into a reduced context (a {@code @WebFluxTest(controllers=...)}
     * slice instantiates every {@code WebFilter} bean but NOT the feature's
     * {@code @Configuration}/{@code @ConfigurationProperties}; an absent provider then reads as
     * "gate off" and the filter simply 404s console paths — which those slices never hit).
     */
    private final ObjectProvider<WorkloadConsoleProperties> propsProvider;
    private final ObjectProvider<WorkloadAuthorizationService> authzProvider;
    private final ObjectProvider<UsageService> usageProvider;

    public WorkloadAuthorizationFilter(ObjectProvider<WorkloadConsoleProperties> propsProvider,
                                       ObjectProvider<WorkloadAuthorizationService> authzProvider,
                                       ObjectProvider<UsageService> usageProvider) {
        this.propsProvider = propsProvider;
        this.authzProvider = authzProvider;
        this.usageProvider = usageProvider;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // Classify the path the way the ROUTER sees it (decoded once, ;params stripped, per
        // segment) — never the raw string, which an encoded spelling such as
        // /bff/admin/%77orkloads/... walks straight past while routing to the same controller.
        List<String> segs = WorkloadPathClassifier.segmentsOf(
                exchange.getRequest().getPath().pathWithinApplication());
        if (!WorkloadPathClassifier.isConsolePath(segs)) {
            return chain.filter(exchange);
        }
        // For logs/audit only: the raw (still percent-encoded, so control-character safe) form.
        String path = exchange.getRequest().getPath().value();

        WorkloadConsoleProperties props = propsProvider.getIfAvailable();
        WorkloadAuthorizationService authz = authzProvider.getIfAvailable();
        // GATE — generator gate off (or no feature wiring) => the whole prefix 404s.
        if (props == null || authz == null || !props.isEnabled()) {
            return deny(exchange, HttpStatus.NOT_FOUND);
        }

        // "." / ".." are matched literally by the router but resolved by a normalising hop:
        // ambiguous, so refused (fail closed) instead of classified.
        if (WorkloadPathClassifier.hasDotSegment(segs)) {
            return deny(exchange, HttpStatus.BAD_REQUEST);
        }

        DangerTier tier = WorkloadPathClassifier.tierOf(segs, exchange.getRequest().getMethod());
        boolean logPath = WorkloadPathClassifier.isLogPath(segs);
        String ns = WorkloadPathClassifier.namespaceOf(segs);
        boolean namespaceOk = ns == null || props.namespaceAllowed(ns);
        String stepUpToken = exchange.getRequest().getHeaders().getFirst("X-Workload-StepUp");

        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .defaultIfEmpty(EMPTY_AUTH)
                // Gate namespace allowlist, then decide and enforce the authorization decision.
                .flatMap(auth -> applyAuthorizationDecision(auth, authz, exchange, chain, path,
                        ns, tier, logPath, namespaceOk, stepUpToken));
    }

    /** Enforce namespace allowlist then ask the authz service to decide, stamping ALLOW or denying. */
    private Mono<Void> applyAuthorizationDecision(Authentication rawAuth,
                                                    WorkloadAuthorizationService authz,
                                                    ServerWebExchange exchange,
                                                    WebFilterChain chain, String path,
                                                    String ns, DangerTier tier, boolean logPath,
                                                    boolean namespaceOk, String stepUpToken) {
        Authentication authentication = rawAuth == EMPTY_AUTH ? null : rawAuth;
        // STEP 0b — out-of-allowlist namespace is a 403 + probe audit BEFORE k8s.
        if (!namespaceOk) {
            auditProbe(authentication, path, ns);
            return deny(exchange, HttpStatus.FORBIDDEN);
        }
        return authz.decide(authentication, tier, logPath, true, stepUpToken)
                .flatMap(decision -> enforceDecision(decision, authentication, exchange, chain, path, tier))
                .onErrorResume(e -> {
                    // fail-closed: any predicate error is a 403, never an ALLOW.
                    log.warn("[workload-authz] predicate error on {}: {}", path, e.toString());
                    return deny(exchange, HttpStatus.FORBIDDEN);
                });
    }

    /** Stamp and proceed on ALLOW; audit and deny on any other decision. */
    private Mono<Void> enforceDecision(WorkloadAccessDecision decision,
                                        Authentication authentication, ServerWebExchange exchange,
                                        WebFilterChain chain, String path, DangerTier tier) {
        if (decision.allow()) {
            // Stamp the decision so the controller can read it (STEP 7 owner-chain attribution).
            exchange.getAttributes().put(ATTR_DECISION, decision);
            return chain.filter(exchange);
        }
        auditDeny(authentication, path, tier, decision);
        return deny(exchange, decision.notFound() ? HttpStatus.NOT_FOUND : HttpStatus.FORBIDDEN);
    }

    /** The attribute key under which the ALLOW decision is stamped for the controllers. */
    public static final String ATTR_DECISION = "workload.console.decision";

    private Mono<Void> deny(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    private void auditProbe(Authentication auth, String path, String ns) {
        record("workload.console.probe.denied", auth);
        log.warn("[workload-authz] PROBE denied: out-of-allowlist namespace '{}' on {}", ns, path);
    }

    private void auditDeny(Authentication auth, String path, DangerTier tier,
                           WorkloadAccessDecision d) {
        record("workload.console.access.denied", auth);
        log.info("[workload-authz] DENY tier={} path={} reason={}", tier, path, d.reason());
    }

    private void record(String action, Authentication auth) {
        try {
            UsageService usage = usageProvider.getIfAvailable();
            if (usage == null) return;
            String actor = auth == null ? "anonymous" : auth.getName();
            usage.record(actor, List.of(RoleName.ADMIN.value()), action).subscribe();
        } catch (Exception ignore) { //NOPMD EmptyCatchBlock - audit is best-effort on deny path
        }
    }

    private static final Authentication EMPTY_AUTH = new Authentication() {
        @Override public java.util.Collection<org.springframework.security.core.GrantedAuthority> getAuthorities() { return List.of(); }
        @Override public Object getCredentials() { return null; }
        @Override public Object getDetails() { return null; }
        @Override public Object getPrincipal() { return null; }
        @Override public boolean isAuthenticated() { return false; }
        @Override public void setAuthenticated(boolean b) { }
        @Override public String getName() { return "anonymous"; }
    };
}
