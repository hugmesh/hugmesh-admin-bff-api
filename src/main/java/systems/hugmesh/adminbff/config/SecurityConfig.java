package systems.hugmesh.adminbff.config;
import systems.hugmesh.authcore.config.SessionCookieWebFilter;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.firewall.ServerWebExchangeFirewall;
import org.springframework.security.web.server.firewall.StrictServerWebExchangeFirewall;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import systems.hugmesh.commons.config.TenancyResourceServerConfig;
import systems.hugmesh.commons.security.CasdoorAuthorities;
import systems.hugmesh.commons.security.DomainRegistry;

/**
 * Casdoor-aware OAuth2 resource-server security for the admin BFF (reactive
 * WebFlux). {@code @EnableReactiveMethodSecurity} activates the
 * {@code @PreAuthorize("hasRole('ADMIN')")} gates on the admin endpoints. The
 * JWT→authority mapping is delegated to the shared, adversarially-verified-safe
 * {@link CasdoorAuthorities} (copied logic-verbatim from hugmesh-gateway):
 * Casdoor's {@code roles} claim (string or {name} objects), {@code permissions}
 * (reserved-prefix entries STRIPPED), and {@code isAdmin} become authorities; every
 * authenticated principal also gets {@code ROLE_USER}; and exactly one issuer-derived
 * {@code DOMAIN_<x>} authority is stamped from the cryptographically-validated
 * {@code iss}.
 *
 * <p><b>Multi-issuer is OPT-IN + backward-compatible.</b> A single-issuer cluster is
 * byte-for-byte unchanged (the lone issuer maps to {@code DOMAIN_default}); the
 * per-brand multi-issuer resolver ({@link TenancyResourceServerConfig}) swaps in ONLY
 * when {@code app.tenancy.issuers} is configured AND
 * {@link DomainRegistry#isMultiIssuer()}.
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    /** Issuer-&gt;domain source of truth. Injected so the converter can stamp the
     *  cryptographically-validated {@code iss} as a {@code DOMAIN_<x>} authority.
     *  Single-issuer clusters get a registry that maps the lone issuer (or no issuer
     *  at all) to {@code DOMAIN_default}, so behaviour is unchanged. */
    private final DomainRegistry domainRegistry;

    /** OPTIONAL per-brand multi-issuer resolver. Present (non-null provider value)
     *  ONLY when {@code app.tenancy.issuers} is configured, via
     *  {@link TenancyResourceServerConfig}. When absent the resource server stays on
     *  the single {@code o.jwt(...)} issuer-uri wiring — byte-for-byte the current
     *  single-issuer path. */
    private final ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
            tenantAuthManagerResolver;

    /**
     * A2 cookie-mode flag — gates BOTH the cookie MINT (in {@code AuthController}) and CSRF
     * here, so there is NEVER a cookie-accepted-without-CSRF window. DEFAULT false (ships
     * dark): CSRF stays disabled and the legacy Bearer-header path is unchanged. {@code @Value}
     * field-injected (the slice tests construct this config via {@code new} and call
     * {@link #setCookieSessionEnabled(boolean)} to drive the flag without a Spring context).
     */
    @Value("${app.session.cookie.enabled:false}")
    private boolean cookieSessionEnabled;

    /**
     * The SHARED in-cluster service credential the {@code /bff/internal/**} subtree is gated
     * on — the SAME {@code app.internal.token} auth-core's {@code InternalTokenWebFilter}
     * enforces and {@code SessionExchangeConfig} STAMPS on this service's own self-loopback,
     * so both halves of the contract read one property. Field-injected ({@code @Value}) like
     * {@link #cookieSessionEnabled} so the security-slice tests can construct this config with
     * {@code new} and drive the flag via {@link #setInternalToken(String)}.
     *
     * <p>BLANK (the dev/test/CI default) means UNARMED — see
     * {@link #internalServiceTokenAuthFilter()} for exactly what that degrades to and why a
     * production deployment can never reach that branch.
     */
    @Value("${app.internal.token:}")
    private String internalToken = "";

    /** Header carrying {@link #internalToken}. Tracks auth-core's
     *  {@code app.internal.token-header} so a deployment that renames it renames it once. */
    @Value("${app.internal.token-header:X-Internal-Token}")
    private String internalTokenHeader = INTERNAL_TOKEN_HEADER_DEFAULT;

    /** D8 MFA marker derivation — {@code app.mfa.enabled} (default {@code false},
     *  ships dark). When off the converter emits the byte-identical legacy
     *  authority set and {@code MFA_SATISFIED} is never produced. Mirrors the
     *  canonical hugmesh-gateway {@code SecurityConfig} wiring. */
    private final boolean mfaEnabled;

    /** D8 MFA freshness window in millis — {@code app.mfa.freshness-window}
     *  (default 10m). A {@code mfa_satisfied_at} stamp older than this (or in the
     *  future) does NOT yield {@code MFA_SATISFIED}. */
    private final long mfaFreshnessWindowMillis;

    public SecurityConfig(DomainRegistry domainRegistry,
                          ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                                  tenantAuthManagerResolver,
                          @Value("${app.mfa.enabled:false}") boolean mfaEnabled,
                          @Value("${app.mfa.freshness-window:600000}") long mfaFreshnessWindowMillis) {
        this.domainRegistry = domainRegistry;
        this.tenantAuthManagerResolver = tenantAuthManagerResolver;
        this.mfaEnabled = mfaEnabled;
        this.mfaFreshnessWindowMillis = mfaFreshnessWindowMillis;
    }

    /** Test seam: drive the A2 cookie-mode flag on a {@code new}-constructed config (the
     *  security-slice path that has no Spring {@code @Value} injection). */
    void setCookieSessionEnabled(boolean enabled) {
        this.cookieSessionEnabled = enabled;
    }

    /** Test seam: arm/disarm the internal-service credential on a {@code new}-constructed
     *  config (the security-slice path that has no Spring {@code @Value} injection). */
    void setInternalToken(String token) {
        this.internalToken = token == null ? "" : token;
    }

    /**
     * The admin route-DEFINITION endpoints address a route by its URL-encoded path
     * prefix as a single path segment (e.g. {@code DELETE
     * /bff/admin/routes/%2Fapi%2Fgames%2F}), so the encoded {@code %2F} slashes must
     * survive to the {@code @PathVariable}. Spring Security's default
     * {@link StrictServerWebExchangeFirewall} rejects encoded slashes with 400; relax
     * exactly that one rule (encoded slash) while keeping every other strict check.
     */
    @Bean
    ServerWebExchangeFirewall encodedSlashTolerantFirewall() {
        var firewall = new StrictServerWebExchangeFirewall();
        firewall.setAllowUrlEncodedSlash(true);
        firewall.setAllowUrlEncodedDoubleSlash(true);
        return firewall;
    }

    /**
     * SpringDoc OpenAPI spec + Swagger UI surface — public under dev/test so
     * {@code gen:fetch} can curl the spec without a token, ROLE_ADMIN everywhere else.
     */
    private static final String[] SPEC_PATHS = {
            "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**"
    };

    /**
     * Reactive HTTP RESPONSE-HEADER hardening — the API-DEFENSIVE MINIMUM for a
     * pure-JSON BFF resource server, applied to EVERY {@link SecurityWebFilterChain}.
     *
     * <p>This BFF is NOT the TLS front door — it is a no-document JSON resource server
     * that ALWAYS sits behind the shared hugmesh-gateway, which emits the full
     * browser-policy set (HSTS / Permissions-Policy / COOP / CORP / the UI-shell CSP)
     * ONCE at the single TLS-terminating PEP so 12 configs can't drift (NIST 800-228
     * sec 3-4). So this chain deliberately OMITS HSTS (meaningless over plaintext
     * intra-mesh, and misleading to assert from a non-edge hop) and Permissions-Policy
     * (no document surface to govern). It re-asserts only the defense-in-depth minimum:
     *
     * <ul>
     *   <li><b>Content-Security-Policy: {@code default-src 'none'; frame-ancestors 'none'}</b>
     *       — a JSON API serves no document, scripts, or framed content; the lockdown CSP
     *       is belt-and-braces should a response ever be mis-typed as HTML.</li>
     *   <li>Spring's reactive SECURE DEFAULTS are KEPT, never disabled —
     *       {@code X-Content-Type-Options: nosniff}, {@code X-Frame-Options: DENY},
     *       {@code Cache-Control: no-store...}, and {@code Referrer-Policy: no-referrer}
     *       (made explicit here so a CSP/Referrer regression is visible).</li>
     * </ul>
     *
     * <p>Purely ADDITIVE: no authz rule, issuer validation, or the correct-by-design
     * {@code csrf.disable()} bearer posture is touched.
     */
    private static void hardenHeaders(ServerHttpSecurity.HeaderSpec h) {
        h.contentSecurityPolicy(csp -> csp.policyDirectives(
                        "default-src 'none'; frame-ancestors 'none'"))
                // Keep Spring's nosniff + X-Frame-Options:DENY + Cache-Control defaults
                // (NOT disabled); make Referrer-Policy:no-referrer explicit.
                .referrerPolicy(rp -> rp.policy(
                        org.springframework.security.web.server.header
                                .ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.NO_REFERRER));
    }

    /**
     * Shared route rules common to BOTH the dev/test and prod filter chains. The ONLY
     * difference between the two profiles is how {@link #SPEC_PATHS} is gated, so every
     * other route lives here to keep the two chains in lockstep.
     */
    private static void commonRoutes(ServerHttpSecurity.AuthorizeExchangeSpec ex) {
        // Probes are public so k8s/Docker healthchecks need no token.
        ex.pathMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll();
        // Pre-auth flow: the caller has no Casdoor JWT yet — the BFF itself enforces
        // the admin-invite gate in the controllers.
        ex.pathMatchers(HttpMethod.POST, "/bff/login").permitAll();
        // Passwordless local-secrets login (sibling of /bff/login). Also pre-token: the
        // controller FULLY validates the agent-vended username+secret against Casdoor before
        // minting a session (LocalSecretVerifier), so permitAll() here matches /bff/login — the
        // credential rigor lives in the controller, not the filter. Fails closed (401) when
        // app.local-login.enabled=false. CSRF-EXEMPT below (a cookie-mint endpoint).
        ex.pathMatchers(HttpMethod.POST, "/bff/login/local").permitAll();
        ex.pathMatchers("/bff/register/**").permitAll();
        // Logout is reachable with ONLY the opaque bff_ session carrier (cookie or Bearer),
        // which the Casdoor resource server does not authenticate — so it is permitAll at the
        // filter chain (idempotent; the controller deletes the row + expires the cookie). It
        // is CSRF-EXEMPT below alongside login/register (the cookie-mint endpoints).
        ex.pathMatchers(HttpMethod.POST, "/bff/sessionOut").permitAll();
        // Public surface — UNAUTHENTICATED endpoints intentionally reachable without a
        // token (the gateway also marks these PUBLIC).
        ex.pathMatchers("/bff/public/**").permitAll();
        // ── Internal service-to-service surface — SERVICE PRINCIPAL ONLY ────────────────
        // This subtree carries the most privilege-bearing endpoints in the fleet: it MINTS
        // an opaque bff_ session for ANY accountId (POST /bff/internal/sessions), swaps a
        // bff_ for the custody-held Casdoor Bearer (POST /bff/internal/session/exchange),
        // lists an account's LIVE session tokens (GET /bff/internal/sessions/{accountId}),
        // creates/completes accounts, stamps token custody, and applies OIDC default roles.
        // Reaching it anonymously is a full account takeover, so it MUST NOT be permitAll().
        //
        // IT USED TO BE. The old rule was permitAll() on the argument that "mTLS is the
        // boundary and the gateway never exposes this prefix publicly". BOTH halves of that
        // argument are false in the deployed topology:
        //   * the fe-gateway's LAST route is `path: /bff/**` -> admin-bff (specs/cluster/apps
        //     /20-gateway-fe.yaml) and NO more-specific route or route-access row covers
        //     /bff/internal/**, so GatewayRouteAccessFilter resolves NO_RULE => FORWARD.
        //     Any authenticated ROLE_USER of any brand could therefore drive this subtree
        //     from the public internet (the gateway's own floor is anyExchange().authenticated()).
        //   * mTLS cannot separate that traffic: the fe-gateway presents ITS OWN cluster-CA
        //     client cert on the proxy leg (HUGMESH_GATEWAY_MTLS_ENABLED=true), i.e. the
        //     handshake succeeds ON THE ATTACKER'S BEHALF. Cert-CN pinning cannot help either
        //     — the gateway is also the LEGITIMATE caller of /session/introspect.
        // What actually separates the two is the ONE credential the gateway stamps on its
        // back-channel calls but NOT on proxied browser traffic: the shared internal token.
        //
        // So the Spring layer now enforces that credential instead of trusting the transport:
        // ROLE_SERVICE, mirroring user-bff's /bff/user/internal/** floor (and mesh-bff's
        // bridge-sync ingest). Deliberately NOT hasAnyRole(SERVICE, ADMIN, SUPERADMIN):
        // ADMIN/SUPERADMIN are HUMAN-reachable and would re-open the takeover; the role
        // hierarchy has no edge to SERVICE, so even SUPERADMIN is denied here.
        // Two principals satisfy it:
        //   1. a Casdoor client_credentials SERVICE JWT (no human login yields ROLE_SERVICE) —
        //      the mechanism federation-api and user-bff already gate their internal APIs on;
        //   2. the in-cluster X-Internal-Token, promoted to a SERVICE principal by
        //      {@link #internalServiceTokenAuthFilter()} — which is what EVERY existing caller
        //      (fe-gateway introspect/exchange, user-bff AdminBffInternalClient, actions'
        //      OIDC hook, the image-gen Job, the go-live host agent, node self-report,
        //      phone-wizard) actually presents today, so no caller contract changes.
        // A future endpoint mounted under this prefix now inherits the SERVICE floor instead
        // of silently inheriting permitAll().
        ex.pathMatchers("/bff/internal/**").hasRole("SERVICE");
        // Fleet-owner surface — the ONE /bff/admin/** path a non-superadmin FLEET_ADMIN
        // capability reaches. MUST precede the generic /bff/admin/** rule below (Spring
        // authorizeExchange is first-match-wins) or a pure FLEET_ADMIN (not ADMIN) would be
        // denied at the coarse ROLE_ADMIN gate. The owner+domain tenancy wall + the fleet
        // entitlement gate are enforced downstream in PhoneFleetOwnerController — this coarse
        // gate only admits the three roles that can reach it at all.
        ex.pathMatchers("/bff/admin/phone-fleet/**").hasAnyRole("FLEET_ADMIN", "ADMIN", "SUPERADMIN");
        // Admin surface — defence-in-depth on top of the gateway's route-access rules.
        // SUPERADMIN added so the cross-domain infra super-role reaches the coarse
        // admin gate (it is a strict superset of ADMIN); the per-row DOMAIN scoping of
        // an ADMIN's reach (admin sees ONLY their brand's rows; SUPERADMIN sees all) is
        // enforced downstream in the service/query layer via the validated issuer.
        ex.pathMatchers("/bff/admin/**").hasAnyRole("ADMIN", "SUPERADMIN");
        // Superadmin-only surface (cross-domain infra control plane). Covers the
        // games-services global catalog + per-domain offers AND the App-Store
        // curation/profiles/deployments (schema 100/101/102). Coarse SUPERADMIN gate here
        // as defence-in-depth on top of the gateway route-access rules AND the per-method
        // @PreAuthorize("hasRole('SUPERADMIN')") on each endpoint — an ADMIN never even
        // reaches a /bff/superadmin/** controller. These endpoints take the target
        // {domain} as an explicit path segment (never a body field) and are therefore
        // deliberately NOT per-row DOMAIN-scoped on the superadmin side.
        ex.pathMatchers("/bff/superadmin/**").hasRole("SUPERADMIN");
        // Games app-store per-domain instance surface. Coarse gate = any of the three
        // games-services roles (the per-method @PreAuthorize on each endpoint is the real
        // gate: create needs GAMES_SERVICES_ADMIN; run/stop also accepts
        // GAMES_SERVICES_RUNNER; read needs GAMES_SERVICES). PrincipalDomain scopes every row
        // to the caller's own brand downstream.
        ex.pathMatchers("/bff/games-services/**")
                .hasAnyRole("GAMES_SERVICES", "GAMES_SERVICES_ADMIN", "GAMES_SERVICES_RUNNER");
        // Authenticated surface feeds (home/forum announcement banners).
        ex.pathMatchers("/bff/announcements/**").authenticated();
        // Mastodon-ui appearance-default READ surface: any authenticated caller reads
        // their OWN brand's admin-configured default (never another brand's — enforced
        // downstream via PrincipalDomain). The write side is
        // /bff/admin/mastodon/appearance-default (the ADMIN/SUPERADMIN coarse gate above).
        ex.pathMatchers("/bff/mastodon/appearance-default").authenticated();
        // Desktop-app-governance DISCOVER registry — the BFF-forwarded, domain-locked
        // Flatpak/OCI index the Plasma Discover store points at. Coarse gate = the brand's
        // `discover` role (a non-discover SSO user is 403). The DOMAIN-LOCK + enabled-only
        // filtering is the real boundary downstream (DesktopRegistryService): the endpoint
        // serves ONLY the caller's-issuer domain's ENABLED refs. The catalog CRUD + sudo
        // grant/revoke + entitlement-read + install-request list/decide + remote-install
        // live under /bff/admin/desktop/** (the ADMIN/SUPERADMIN coarse gate above).
        ex.pathMatchers("/bff/desktop/registry/**").hasRole("DISCOVER");
        // Desktop install-REQUEST submit + the requester's own-request list: any
        // AUTHENTICATED desktop user may ask their admin to allow/install an app
        // (owner == subject enforced in the service/query; a user only ever sees/creates
        // their OWN requests). The admin decide/list surface is /bff/admin/desktop/**.
        ex.pathMatchers("/bff/desktop/install-requests/**").authenticated();
    }

    /**
     * Dev / test profile: the OpenAPI spec + Swagger UI are PUBLIC.
     */
    @Bean
    @Profile({"dev", "test"})
    SecurityWebFilterChain devFilterChain(ServerHttpSecurity http) {
        applyCsrf(http);
        applyInternalServiceAuth(http);
        return http
                .headers(SecurityConfig::hardenHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).permitAll();
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::resourceServer)
                .build();
    }

    /**
     * Production profile (default — active whenever neither {@code dev} nor
     * {@code test} is): the OpenAPI spec + Swagger UI require ROLE_ADMIN.
     */
    @Bean
    @Profile("!dev & !test")
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        applyCsrf(http);
        applyInternalServiceAuth(http);
        return http
                .headers(SecurityConfig::hardenHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).hasAnyRole("ADMIN", "SUPERADMIN");
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::resourceServer)
                .build();
    }

    /** The opaque session-token prefix — mirrors {@link SessionCookieWebFilter}. */
    private static final String BFF_TOKEN_PREFIX = "bff_";

    /** The internal service-to-service prefix gated to {@code ROLE_SERVICE} above. */
    static final String INTERNAL_PREFIX = "/bff/internal/";

    /** Default header carrying the shared internal-service credential (auth-core parity). */
    static final String INTERNAL_TOKEN_HEADER_DEFAULT = "X-Internal-Token";

    /** The authority the internal-service credential is promoted to — the SAME
     *  {@code ROLE_SERVICE} a Casdoor client_credentials token carries. */
    private static final String SERVICE_AUTHORITY = "ROLE_SERVICE";

    /**
     * Install the internal-service authentication leg on a chain. Added just BEFORE
     * {@link SecurityWebFiltersOrder#AUTHORIZATION} — i.e. AFTER every authentication filter
     * (the Casdoor resource server included) and immediately BEFORE the authorization
     * decision. Position is load-bearing: an authentication filter that ran later would
     * OVERWRITE the reactor-context principal this one publishes, so a caller presenting the
     * in-cluster credential could silently lose its SERVICE identity. Placing it last also
     * makes that credential — not a Bearer that happens to ride along — the decider on the
     * internal subtree.
     */
    private void applyInternalServiceAuth(ServerHttpSecurity http) {
        http.addFilterBefore(internalServiceTokenAuthFilter(), SecurityWebFiltersOrder.AUTHORIZATION);
    }

    /**
     * Promote the shared in-cluster credential ({@code app.internal.token}, presented in
     * {@code app.internal.token-header}) to an authenticated {@code ROLE_SERVICE} principal on
     * the {@code /bff/internal/**} subtree — the second of the two principals the SERVICE floor
     * in {@link #commonRoutes} admits, and the one EVERY existing caller presents today (see
     * that rule's comment for the caller inventory).
     *
     * <p><b>What it does NOT do.</b> It never denies: a request without a valid credential is
     * simply left unauthenticated, so the {@code hasRole("SERVICE")} rule denies it through the
     * normal path — anonymous ⇒ 401 via the bearer entry point, human JWT ⇒ 403. Keeping the
     * refusal in the authorization layer is the point of this fix: the deny is visible in the
     * route policy rather than buried in a filter that runs after it. auth-core's
     * {@code InternalTokenWebFilter} still runs (LOWEST_PRECEDENCE, i.e. after this whole
     * chain) as the unchanged belt-and-braces on the transport-adjacent side.
     *
     * <p><b>Comparison is constant-time</b> (length-independent {@link MessageDigest#isEqual})
     * so the credential cannot be recovered a byte at a time — same treatment auth-core gives
     * it.
     *
     * <p><b>UNARMED (blank token) = the legacy permitAll behaviour, dev/test only.</b> When no
     * credential is configured this mints the SERVICE principal for every internal request, so
     * a local compose run / CI slice / {@code ADMIN_BFF_PROFILES=casdoor,dev} stack behaves
     * BYTE-FOR-BYTE as before this change (auth-core's filter uses the identical "blank ⇒
     * no-op" convention, and the compose stack ships with {@code INTERNAL_TOKEN} unset). A
     * PRODUCTION deployment can never reach that branch: {@link InternalSurfaceTokenBootGuard}
     * (profile {@code !dev & !test}) refuses to boot with a blank credential, exactly as
     * auth-core's {@code InternalSurfaceBootGuard} refuses to boot without mTLS.
     */
    private WebFilter internalServiceTokenAuthFilter() {
        return (exchange, chain) -> {
            if (!exchange.getRequest().getPath().value().startsWith(INTERNAL_PREFIX)) {
                return chain.filter(exchange);
            }
            if (internalToken == null || internalToken.isBlank()) {
                // UNARMED — dev/test parity with the historic permitAll (see javadoc).
                return chain.filter(exchange).contextWrite(
                        ReactiveSecurityContextHolder.withAuthentication(serviceAuthentication("internal-unarmed")));
            }
            String header = (internalTokenHeader == null || internalTokenHeader.isBlank())
                    ? INTERNAL_TOKEN_HEADER_DEFAULT : internalTokenHeader;
            String presented = exchange.getRequest().getHeaders().getFirst(header);
            if (presented != null && constantTimeEquals(presented, internalToken)) {
                return chain.filter(exchange).contextWrite(
                        ReactiveSecurityContextHolder.withAuthentication(serviceAuthentication("internal-token")));
            }
            // No valid credential: stay unauthenticated and let hasRole("SERVICE") deny.
            return chain.filter(exchange);
        };
    }

    /** The synthetic SERVICE principal — the three-arg AUTHENTICATED
     *  {@link UsernamePasswordAuthenticationToken} form, same carrier the gateway's
     *  {@code BffSessionAuthFilter} uses to hand a non-JWT identity to the authorization layer. */
    private static Authentication serviceAuthentication(String principal) {
        return new UsernamePasswordAuthenticationToken(
                principal, null, List.of(new SimpleGrantedAuthority(SERVICE_AUTHORITY)));
    }

    /** Length-independent constant-time comparison (no early-exit timing leak). */
    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /** The double-submit CSRF header the cookie-mode UIs echo the token in. */
    static final String CSRF_HEADER = "X-CSRF-TOKEN";

    /**
     * A2 CSRF wiring — enabled IN THE SAME FLAG as the cookie MINT
     * ({@code app.session.cookie.enabled}), so there is NEVER a cookie-accepted-without-CSRF
     * window. DEFAULT false (ships dark): CSRF is DISABLED and the chain is byte-for-byte the
     * legacy {@code csrf(disable)} behaviour.
     *
     * <p>When ON: double-submit cookie CSRF ({@link CookieServerCsrfTokenRepository} with a
     * JS-readable token cookie so the SPA can echo it in the {@value #CSRF_HEADER} header). The
     * {@link #cookieCsrfMatcher() require-matcher} requires CSRF ONLY for a MUTATING request
     * that carries the {@code bff_session} cookie AND does NOT carry a REAL client-sent
     * {@code bff_} Bearer header — so the LEGACY Bearer-header path stays CSRF-EXEMPT (a
     * programmatic API client with a Bearer token is not a CSRF target), and the cookie-mint
     * endpoints (login/register/sessionOut) are exempt (the client has no CSRF token yet). A
     * cookie-carried mutation WITHOUT a valid CSRF token is a 403.
     *
     * <p><b>Bridge-synthesised Bearer is NOT a real Bearer.</b> {@link SessionCookieWebFilter}
     * runs ahead of the security chain and, for a cookie-only request, rewrites the request with
     * a synthesised {@code Authorization: Bearer bff_...}. The matcher therefore ignores that
     * synthesised header (it consults {@link SessionCookieWebFilter#SYNTHESISED_BEARER_ATTR}) so
     * cookie-borne mutations still require CSRF — there is NO window where a cookie is accepted
     * without CSRF once the flag is on.
     */
    private void applyCsrf(ServerHttpSecurity http) {
        if (!cookieSessionEnabled) {
            http.csrf(ServerHttpSecurity.CsrfSpec::disable);
            return;
        }
        http.csrf(c -> c
                .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                .requireCsrfProtectionMatcher(cookieCsrfMatcher()));
    }

    /**
     * Require CSRF only when ALL hold: the method is mutating (default CSRF method set —
     * POST/PUT/PATCH/DELETE), the request carries the {@code bff_session} cookie, and it does
     * NOT carry a REAL client-sent {@code bff_} Bearer header (a bridge-SYNTHESISED one, flagged
     * via {@link SessionCookieWebFilter#SYNTHESISED_BEARER_ATTR}, does NOT count), and it is not
     * a cookie-mint endpoint (login/register/sessionOut). Otherwise NOT-MATCH (CSRF skipped) so
     * the legacy Bearer-header world is untouched.
     */
    private ServerWebExchangeMatcher cookieCsrfMatcher() {
        ServerWebExchangeMatcher mutating = ServerWebExchangeMatchers.matchers(
                ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/**"),
                ServerWebExchangeMatchers.pathMatchers(HttpMethod.PUT, "/**"),
                ServerWebExchangeMatchers.pathMatchers(HttpMethod.PATCH, "/**"),
                ServerWebExchangeMatchers.pathMatchers(HttpMethod.DELETE, "/**"));
        ServerWebExchangeMatcher mintExempt = ServerWebExchangeMatchers.matchers(
                ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/bff/login"),
                ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/bff/login/local"),
                ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/bff/sessionOut"),
                ServerWebExchangeMatchers.pathMatchers("/bff/register/**"));
        // Apply cookie CSRF matching: require CSRF only for cookie-carried mutations.
        return exchange -> mutating.matches(exchange)
                .flatMap(m -> resolveCookieCsrfMatch(exchange, m, mintExempt));
    }

    /** Decide whether a mutating exchange must present a CSRF token.
     *  Non-match → CSRF-exempt; match → require CSRF. */
    private static Mono<ServerWebExchangeMatcher.MatchResult> resolveCookieCsrfMatch(
            ServerWebExchange exchange,
            ServerWebExchangeMatcher.MatchResult mutatingMatch,
            ServerWebExchangeMatcher mintExempt) {
        if (!mutatingMatch.isMatch()) {
            return ServerWebExchangeMatcher.MatchResult.notMatch();
        }
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(
                SessionCookieWebFilter.SESSION_COOKIE);
        boolean hasSessionCookie = cookie != null && cookie.getValue() != null
                && cookie.getValue().startsWith(BFF_TOKEN_PREFIX);
        if (!hasSessionCookie) {
            // Bearer-header path (or unauthenticated): CSRF-exempt.
            return ServerWebExchangeMatcher.MatchResult.notMatch();
        }
        // CRITICAL: consult the ORIGINAL client-sent carrier, not the bridge-synthesised one.
        boolean bridgeSynthesised = Boolean.TRUE.equals(
                exchange.getAttribute(SessionCookieWebFilter.SYNTHESISED_BEARER_ATTR));
        String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        boolean bearerBff = auth != null && auth.startsWith("Bearer ")
                && auth.substring(7).trim().startsWith(BFF_TOKEN_PREFIX);
        if (bearerBff && !bridgeSynthesised) {
            // Genuine client-sent bff_ Bearer (legacy programmatic carrier): CSRF-exempt.
            return ServerWebExchangeMatcher.MatchResult.notMatch();
        }
        // Cookie-carried mutation: exempt the cookie-mint endpoints, require CSRF elsewhere.
        return mintExempt.matches(exchange).flatMap(mint -> mint.isMatch()
                ? ServerWebExchangeMatcher.MatchResult.notMatch()
                : ServerWebExchangeMatcher.MatchResult.match());
    }

    /**
     * Resource-server wiring shared by both profile chains. Multi-issuer is OPT-IN:
     * swap to the per-issuer authentication-manager resolver ONLY when BOTH a resolver
     * was contributed by {@link TenancyResourceServerConfig} AND the registry is
     * genuinely multi-issuer (more than the single back-compat entry). Gating on
     * {@code isMultiIssuer()} — not merely {@code resolver != null} — keeps a
     * single-issuer cluster on the EXISTING jwk-set-uri {@code o.jwt(...)} decoder path.
     * In true multi-brand mode each trusted per-brand Casdoor validates its own tokens
     * (unknown iss -&gt; 401, fail-closed).
     */
    private void resourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec o) {
        // The OPAQUE bff_ session token is NOT a Casdoor JWT. The A2 cookie bridge synthesises a
        // `Authorization: Bearer bff_...` from the session cookie, and existing clients also carry
        // the bff_ token as a Bearer — so the resource server MUST NOT try to authenticate a bff_
        // token as a JWT (a present-but-invalid Bearer would 401 even on a permitAll path,
        // breaking cookie-mode + the standalone bff_ flow). Skip bff_ Bearers at the token
        // resolver so they fall through to the controller's app-layer session resolution. A real
        // Casdoor JWT Bearer is unaffected. UNFLAGGED — purely additive, the legacy JWT path is
        // byte-for-byte unchanged for non-bff_ tokens.
        o.bearerTokenConverter(skipBffTokenConverter());
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenantAuthManagerResolver.getIfAvailable();
        if (resolver != null && domainRegistry.isMultiIssuer()) {
            o.authenticationManagerResolver(resolver);
        } else {
            o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter()));
        }
    }

    /**
     * A bearer-token converter that resolves a Casdoor JWT Bearer normally but returns EMPTY for
     * an opaque {@code bff_} Bearer — so the resource server never attempts to JWT-decode a bff_
     * session token (it is resolved at the app layer instead). Empty == "no bearer present" to
     * the resource server, so a bff_-only request is treated as unauthenticated-by-bearer and the
     * authorization rules (permitAll / authenticated) apply as if no Bearer was sent.
     */
    private static org.springframework.security.web.server.authentication.ServerAuthenticationConverter
            skipBffTokenConverter() {
        org.springframework.security.oauth2.server.resource.web.server.authentication
                .ServerBearerTokenAuthenticationConverter delegate =
                new org.springframework.security.oauth2.server.resource.web.server.authentication
                        .ServerBearerTokenAuthenticationConverter();
        return exchange -> {
            String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (auth != null && auth.startsWith("Bearer ")
                    && auth.substring(7).trim().startsWith(BFF_TOKEN_PREFIX)) {
                return Mono.empty();   // opaque bff_ session -> not a JWT, app-layer resolves it.
            }
            return delegate.convert(exchange);
        };
    }

    /**
     * Method-security role hierarchy — SUPERADMIN-only edges. Deliberately MINIMAL:
     * SUPERADMIN is a strict superset of admin/mod/user, but {@code ROLE_ADMIN} and
     * {@code ROLE_MOD} are documented SIBLINGS (no {@code ADMIN > MOD} edge) and the
     * AND-intersection composites are intentionally ABSENT — so a hierarchy can NEVER
     * let a plain ADMIN satisfy an intersection role. This bean only smooths
     * {@code @PreAuthorize} ergonomics inside method security (e.g. SUPERADMIN
     * satisfies {@code hasRole('ADMIN')}); the per-row DOMAIN predicate still scopes
     * an ADMIN to their own brand.
     */
    @Bean
    RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy(
                "ROLE_SUPERADMIN > ROLE_ADMIN\n" +
                "ROLE_SUPERADMIN > ROLE_MOD\n" +
                "ROLE_SUPERADMIN > ROLE_USER");
    }

    @Bean
    MethodSecurityExpressionHandler adminMethodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        var handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }

    private ReactiveJwtAuthenticationConverter jwtConverter() {
        var converter = new ReactiveJwtAuthenticationConverter();
        // Carry the D8 MfaConfig so the single-issuer path derives the MFA_SATISFIED
        // marker identically to the multi-issuer path. When app.mfa.enabled=false
        // (the dark default) this is byte-identical to the legacy converter.
        converter.setJwtGrantedAuthoritiesConverter(
                CasdoorAuthorities.converter(domainRegistry,
                        new CasdoorAuthorities.MfaConfig(mfaEnabled, mfaFreshnessWindowMillis)));
        return converter;
    }

    /**
     * Casdoor claim -&gt; Spring authority mapping bound to the given
     * {@link DomainRegistry}. Delegates to the shared {@link CasdoorAuthorities} so the
     * single-issuer path here and the optional multi-issuer path
     * ({@link TenancyResourceServerConfig}) stay byte-identical. MFA derivation OFF —
     * the production single-issuer path uses {@link #jwtConverter()} (which carries the
     * D8 {@code MfaConfig}); this static overload keeps the legacy authority set for the
     * back-compat unit-test seams.
     */
    static Converter<Jwt, Flux<GrantedAuthority>> casdoorAuthoritiesConverter(DomainRegistry domainRegistry) {
        return CasdoorAuthorities.converter(domainRegistry);
    }

    /**
     * Back-compat overload for unit tests: a converter wired to a single-issuer
     * registry (every token maps to {@code DOMAIN_default}). Production code uses the
     * injected-registry overload above.
     */
    static Converter<Jwt, Flux<GrantedAuthority>> casdoorAuthoritiesConverter() {
        return CasdoorAuthorities.converter(new DomainRegistry("", ""));
    }
}
