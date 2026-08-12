package net.hugmesh.adminbff.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Catch-all stand-in for every {@code /bff/internal/**} handler. The real endpoints live in
 * eight controllers ({@code InternalAccountController}, {@code DeviceEnrollmentController},
 * {@code PhoneIngestController}, {@code ImageBuildIngestController},
 * {@code GoLiveInternalController}, {@code DesktopSudoEntitlementController},
 * {@code DomainCapabilityInternalController}, {@code OidcFirstLoginController}); their ONLY
 * coarse wall is the path matcher in {@link SecurityConfig}, so one catch-all handler proves
 * the wall for all of them AND for a path no controller claims yet (the fail-closed-by-default
 * property this fix adds).
 */
@RestController
class InternalProbes {
    @RequestMapping("/bff/internal/**")
    String any() {
        return "reached";
    }
}

/**
 * ROLE MATRIX for the {@code /bff/internal/**} service-to-service subtree with the shared
 * internal-service credential ARMED ({@code app.internal.token} set) — the state every
 * production deployment is in ({@link InternalSurfaceTokenBootGuard} refuses to boot
 * otherwise).
 *
 * <p><b>What this pins.</b> Before this fix the subtree was {@code permitAll()} at the Spring
 * layer, so EVERY case below returned 200 — including an anonymous caller arriving through the
 * fe-gateway's {@code /bff/**} route, which is how the public internet reaches this service.
 * The matrix now is:
 *
 * <ul>
 *   <li>anonymous ⇒ 401 (bearer entry point);</li>
 *   <li>authenticated-but-wrong-role — USER / ADMIN / SUPERADMIN, i.e. every HUMAN role,
 *       including the cross-domain super-role ⇒ 403 (the hierarchy has no edge to SERVICE);</li>
 *   <li>{@code ROLE_SERVICE} (a Casdoor client_credentials token) ⇒ through;</li>
 *   <li>a valid {@code X-Internal-Token} (what the gateways / user-bff / actions / the
 *       in-cluster Jobs and node agents actually present) ⇒ through;</li>
 *   <li>a WRONG or absent internal token ⇒ 401.</li>
 * </ul>
 *
 * <p>auth-core's {@code InternalTokenWebFilter} is deliberately EXCLUDED from this slice (a
 * {@code @WebFluxTest} would otherwise pick it up — it is a {@code WebFilter} {@code @Component}
 * on the scanned {@code net.hugmesh.authcore} path). That is the point: it runs at
 * {@code LOWEST_PRECEDENCE}, i.e. AFTER the whole security chain, so with it in the picture an
 * anonymous 401 proves nothing about the authorization layer — the old {@code permitAll()}
 * would produce the same status. Excluding it makes every assertion here a statement about the
 * route policy itself, and makes this test FAIL against the old rule.
 * {@code DesktopSudoEntitlementInternalTokenTest} covers the combined stack.
 */
@WebFluxTest(controllers = InternalProbes.class,
        excludeFilters = @org.springframework.context.annotation.ComponentScan.Filter(
                type = org.springframework.context.annotation.FilterType.ASSIGNABLE_TYPE,
                classes = net.hugmesh.authcore.config.InternalTokenWebFilter.class))
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class})
@TestPropertySource(properties = {
        "app.internal.token=s3cret",
        "app.internal.token-header=X-Internal-Token"
})
class InternalSurfaceRoleMatrixTest {

    @Autowired ApplicationContext context;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    WebTestClient client;

    @BeforeEach
    void setUp() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    /**
     * One entry per REAL internal endpoint (method + path as its controller maps it), plus a
     * path no controller claims — the regression pin for "a new endpoint under this prefix must
     * not silently inherit an open gate".
     */
    static Stream<org.junit.jupiter.params.provider.Arguments> internalPaths() {
        return Stream.of(
                // InternalAccountController — the account/session data plane.
                arguments(HttpMethod.POST, "/bff/internal/accounts/ensure"),
                arguments(HttpMethod.GET, "/bff/internal/accounts/acct-1"),
                arguments(HttpMethod.POST, "/bff/internal/accounts/acct-1/complete"),
                arguments(HttpMethod.GET, "/bff/internal/accounts/acct-1/namespaces"),
                arguments(HttpMethod.GET, "/bff/internal/allowlist/google/alice"),
                arguments(HttpMethod.POST, "/bff/internal/sessions"),
                arguments(HttpMethod.DELETE, "/bff/internal/sessions/bff_tok"),
                arguments(HttpMethod.GET, "/bff/internal/sessions/acct-1"),
                arguments(HttpMethod.GET, "/bff/internal/session/introspect"),
                arguments(HttpMethod.POST, "/bff/internal/custody/stamp"),
                arguments(HttpMethod.POST, "/bff/internal/session/exchange"),
                // The node / Job / host-agent / IdP legs.
                arguments(HttpMethod.POST, "/bff/internal/device-enrollment/self-report"),
                arguments(HttpMethod.POST, "/bff/internal/device-registry/phone-ingest"),
                arguments(HttpMethod.POST, "/bff/internal/image-builds/b-1/ingest"),
                arguments(HttpMethod.POST, "/bff/internal/image-builds/b-1/progress"),
                arguments(HttpMethod.POST, "/bff/internal/go-live/gl-1/applied-ack"),
                arguments(HttpMethod.GET, "/bff/internal/desktop/sudo/entitlement?subject=a&deviceId=d"),
                arguments(HttpMethod.GET, "/bff/internal/domain-capabilities/brandx/user_mesh_devices"),
                arguments(HttpMethod.POST, "/bff/internal/oidc/first-login"),
                // No controller claims this one — it must be denied, not inherited-open.
                arguments(HttpMethod.GET, "/bff/internal/some-future-endpoint"));
    }

    @ParameterizedTest(name = "{0} {1} — anonymous is 401")
    @MethodSource("internalPaths")
    void anonymous_is401(HttpMethod method, String path) {
        client.method(method).uri(path).exchange().expectStatus().isUnauthorized();
    }

    @ParameterizedTest(name = "{0} {1} — plain USER is 403")
    @MethodSource("internalPaths")
    void authenticatedUser_is403(HttpMethod method, String path) {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .method(method).uri(path).exchange().expectStatus().isForbidden();
    }

    @ParameterizedTest(name = "{0} {1} — ADMIN is 403")
    @MethodSource("internalPaths")
    void admin_is403(HttpMethod method, String path) {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_ADMIN")))
                .method(method).uri(path).exchange().expectStatus().isForbidden();
    }

    @ParameterizedTest(name = "{0} {1} — SUPERADMIN is 403")
    @MethodSource("internalPaths")
    void superadmin_is403(HttpMethod method, String path) {
        // SUPERADMIN is a strict superset of the HUMAN roles, but the hierarchy has NO edge to
        // SERVICE — a human super-role must never be able to mint a session for another account.
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN")))
                .method(method).uri(path).exchange().expectStatus().isForbidden();
    }

    @ParameterizedTest(name = "{0} {1} — ROLE_SERVICE JWT gets through")
    @MethodSource("internalPaths")
    void serviceJwt_reachesHandler(HttpMethod method, String path) {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_SERVICE")))
                .method(method).uri(path).exchange().expectStatus().isOk();
    }

    @ParameterizedTest(name = "{0} {1} — valid internal token gets through")
    @MethodSource("internalPaths")
    void validInternalToken_reachesHandler(HttpMethod method, String path) {
        client.method(method).uri(path).header("X-Internal-Token", "s3cret")
                .exchange().expectStatus().isOk();
    }

    @ParameterizedTest(name = "{0} {1} — wrong internal token is 401")
    @MethodSource("internalPaths")
    void wrongInternalToken_is401(HttpMethod method, String path) {
        client.method(method).uri(path).header("X-Internal-Token", "WRONG")
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void internalTokenDecidesTheSubtree_evenWhenAHumanJwtRidesAlong() {
        // The in-cluster credential is the authority on this subtree: it is promoted to the
        // SERVICE principal AFTER the resource server has run, so a caller that happens to
        // forward a human JWT alongside it is still a SERVICE caller here (and a human JWT
        // alone is still denied — see admin_is403 / superadmin_is403).
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .post().uri("/bff/internal/sessions").header("X-Internal-Token", "s3cret")
                .exchange().expectStatus().isOk();
    }

    @Test
    void nonInternalPathsAreUnaffected_byTheInternalCredential() {
        // The credential grants SERVICE on the internal subtree ONLY — presenting it must never
        // open an admin path (which would turn a shared service secret into an admin bypass).
        client.get().uri("/bff/admin/allowlist").header("X-Internal-Token", "s3cret")
                .exchange().expectStatus().isUnauthorized();
    }

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) {
            out.add(new SimpleGrantedAuthority(n));
        }
        return out;
    }
}
