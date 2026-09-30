package net.hugmesh.adminbff.config;
import net.hugmesh.authcore.config.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;

/**
 * A2 CSRF slice — proves the double-submit CSRF (enabled IN THE SAME flag as the cookie mint)
 * fires ONLY for a cookie-carried mutation, and that the legacy Bearer-header path stays
 * CSRF-EXEMPT. Drives a controller THROUGH the real prod {@link SecurityConfig#filterChain}
 * with the cookie flag ON ({@code setCookieSessionEnabled(true)}), no Spring context.
 */
class CookieCsrfSliceTest {

    @RestController
    static class Probe {
        // A permitAll mutation so the test isolates CSRF (not authz): /bff/sessionOut is permitAll.
        @PostMapping("/bff/sessionOut")
        String sessionOut() {
            return "ok";
        }
        // An authenticated mutation under /bff/announcements (a non-mint path) to prove a
        // cookie-carried mutation needs CSRF; we assert the 403 happens BEFORE auth.
        @PostMapping("/bff/announcements/x")
        String mutate() {
            return "ok";
        }
    }

    private static ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> provider(
            ReactiveAuthenticationManagerResolver<ServerWebExchange> value) {
        return new ObjectProvider<>() {
            @Override public ReactiveAuthenticationManagerResolver<ServerWebExchange> getObject() {
                return value;
            }
            @Override public ReactiveAuthenticationManagerResolver<ServerWebExchange> getObject(Object... a) {
                return value;
            }
            @Override public ReactiveAuthenticationManagerResolver<ServerWebExchange> getIfAvailable() {
                return value;
            }
            @Override public ReactiveAuthenticationManagerResolver<ServerWebExchange> getIfUnique() {
                return value;
            }
        };
    }

    /**
     * Build the chain via the MULTI-ISSUER resolver branch so the resource server does NOT
     * eagerly build a single-issuer jwt decoder (which needs an issuer-uri the slice has none
     * of). The CSRF assertions don't authenticate: the cookie-mutation 403 fires BEFORE auth,
     * and the bearer/permitAll cases reach the controller without ever invoking the manager.
     */
    private WebTestClient client(boolean cookieEnabled) {
        return clientInternal(cookieEnabled, false);
    }

    /**
     * Production filter ORDERING: the {@link SessionCookieWebFilter} cookie->Bearer bridge runs
     * AHEAD of the security chain (just as in prod, {@code HIGHEST_PRECEDENCE+5} < the chain
     * proxy's order), so the synthesised {@code Authorization: Bearer bff_...} is present when the
     * CSRF matcher runs. Used by the regression test that proves the bridge does NOT defeat CSRF.
     */
    private WebTestClient clientWithBridge(boolean cookieEnabled) {
        return clientInternal(cookieEnabled, true);
    }

    private WebTestClient clientInternal(boolean cookieEnabled, boolean withBridge) {
        // Two trusted issuers -> isMultiIssuer() true -> the o.authenticationManagerResolver(...)
        // branch is taken (no jwt-decoder build).
        DomainRegistry registry = new DomainRegistry(
                "https://x.example=ignored", "https://x.example=brandx,https://y.example=brandy");
        // The manager fails with an AuthenticationException (bff_ is not a JWT) so a stray bearer
        // maps to 401 -> a permitAll path still reaches the controller; an authenticated path 401s.
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                exchange -> Mono.just(authentication -> Mono.error(
                        new org.springframework.security.authentication.BadCredentialsException(
                                "not exercised in CSRF slice")));
        SecurityConfig config = new SecurityConfig(registry, provider(resolver), false, 600_000L, "X-Internal-Token");
        config.setCookieSessionEnabled(cookieEnabled);
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        var builder = WebTestClient.bindToController(new Probe());
        if (withBridge) {
            // Mirror prod ordering: the cookie bridge runs FIRST, then the security chain proxy.
            builder.webFilter(new SessionCookieWebFilter(), new WebFilterChainProxy(chain));
        } else {
            builder.webFilter(new WebFilterChainProxy(chain));
        }
        return builder.build();
    }

    @Test
    void cookieCarriedMutation_withoutCsrfToken_is403() {
        // cookie mode ON: a mutation carrying the bff_session cookie but NO CSRF token -> 403.
        client(true).post().uri("/bff/announcements/x")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_abc")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void bearerHeaderMutation_isCsrfExempt() {
        // cookie mode ON, but the request uses the LEGACY Bearer carrier (no session cookie) ->
        // CSRF-exempt. It is a permitAll path, so it reaches the controller (200).
        client(true).post().uri("/bff/sessionOut")
                .header("Authorization", "Bearer bff_abc")
                .exchange().expectStatus().isOk();
    }

    @Test
    void cookieCarriedMintEndpoint_isCsrfExempt() {
        // sessionOut is a cookie-mint/clear endpoint -> exempt even when carrying the cookie.
        client(true).post().uri("/bff/sessionOut")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_abc")
                .exchange().expectStatus().isOk();
    }

    @Test
    void cookieFlagOff_noCsrf_mutationPasses() {
        // cookie mode OFF (ships dark): CSRF disabled -> the same cookie-carried mutation is NOT
        // blocked (reaches the permitAll controller).
        client(false).post().uri("/bff/sessionOut")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_abc")
                .exchange().expectStatus().isOk();
    }

    // ---- Production filter-ORDERING regression (the bridge MUST NOT defeat CSRF) ----------------

    /**
     * REGRESSION for the CSRF fail-open finding. With the {@link SessionCookieWebFilter} cookie
     * bridge running AHEAD of the security chain (prod ordering), a cookie-ONLY mutation has its
     * {@code Authorization: Bearer bff_...} synthesised by the bridge BEFORE the CSRF matcher
     * runs. The matcher MUST ignore that synthesised header (consult the bridge's
     * SYNTHESISED_BEARER attribute) and STILL require CSRF -> 403. Before the fix this returned
     * 401 (CSRF skipped, the synthesised Bearer wrongly exempted the request).
     */
    @Test
    void cookieCarriedMutation_throughBridge_withoutCsrfToken_is403() {
        clientWithBridge(true).post().uri("/bff/announcements/x")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_abc")
                .exchange().expectStatus().isForbidden();
    }

    /**
     * Through the SAME prod ordering (bridge first), a REAL client-sent {@code bff_} Bearer (no
     * cookie) stays CSRF-exempt: the bridge does not synthesise anything (it leaves the genuine
     * Bearer untouched and sets no attribute), so the legacy programmatic carrier reaches the
     * permitAll controller (200).
     */
    @Test
    void realBearerMutation_throughBridge_isCsrfExempt() {
        clientWithBridge(true).post().uri("/bff/sessionOut")
                .header("Authorization", "Bearer bff_abc")
                .exchange().expectStatus().isOk();
    }

    /**
     * Through prod ordering, a cookie-carried MINT endpoint (sessionOut) stays exempt even though
     * the bridge synthesises a Bearer for it — the mint-exempt branch fires.
     */
    @Test
    void cookieCarriedMintEndpoint_throughBridge_isCsrfExempt() {
        clientWithBridge(true).post().uri("/bff/sessionOut")
                .cookie(SessionCookieWebFilter.SESSION_COOKIE, "bff_abc")
                .exchange().expectStatus().isOk();
    }
}
