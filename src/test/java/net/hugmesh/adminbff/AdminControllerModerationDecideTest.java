package net.hugmesh.adminbff;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.domainlock.DomainLockService;
import net.hugmesh.adminbff.federation.FederationApiClient;
import net.hugmesh.adminbff.federation.ModerationDecisionDto;
import net.hugmesh.adminbff.iso.IsoRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.urlregistry.UrlRegistryService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.username.UsernameGate;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Security and delegation coverage for {@code POST /bff/admin/moderation/{id}/decide}.
 *
 * <p>This is a security-critical proxy endpoint: it approves or denies user appeals by
 * forwarding to hugmesh-federation-api. Three defence-in-depth layers are validated:
 * <ol>
 *   <li>No token → 401 (unauthenticated).</li>
 *   <li>ROLE_USER only → 403 (insufficient authority, path rule + @PreAuthorize).</li>
 *   <li>ROLE_ADMIN → 200, federation client called with correct id + approve flag.</li>
 *   <li>ROLE_SUPERADMIN → 200 (role hierarchy: SUPERADMIN satisfies hasRole('ADMIN')).</li>
 *   <li>Non-positive id → 400 (@Positive constraint, never hits federation).</li>
 *   <li>Federation client error → 502 Bad Gateway (never leaks a raw 500).</li>
 * </ol>
 */
@WebFluxTest(controllers = AdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class AdminControllerModerationDecideTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    // All AdminController collaborators must be mocked so WebFluxTest can wire the
    // controller without requiring a running database or service layer.
    @MockitoBean RouteAccessService routeAccess;
    @MockitoBean UrlRegistryService urlRegistry;
    @MockitoBean IsoRepository isoRepo;
    @MockitoBean AccountStore store;
    @MockitoBean UsageService usage;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean DomainLockService domainLocks;
    @MockitoBean FederationApiClient federation;
    @MockitoBean CasdoorAdminClient casdoor;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;
    @MockitoBean UsernameGate usernameGate;
    @MockitoBean net.hugmesh.adminbff.capability.DomainCapabilityService domainCapabilities;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    // ── Helper mutators ────────────────────────────────────────────────────────

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER")));
    }

    /**
     * A SUPERADMIN mock that includes the expanded authority set as the real
     * {@link net.hugmesh.commons.security.CasdoorAuthorities} converter would
     * produce after applying the role hierarchy (SUPERADMIN &gt; ADMIN &gt; USER).
     * The {@code mockJwt()} helper bypasses the JWT-to-authority converter entirely,
     * so hierarchy expansion does NOT happen automatically — we must supply the
     * already-expanded authorities that a real SUPERADMIN token would carry after
     * the converter runs. This matches production behaviour: CasdoorAuthorities stamps
     * ROLE_SUPERADMIN, and the RoleHierarchy bean expands it to include ROLE_ADMIN
     * and ROLE_USER when the @PreAuthorize expression is evaluated.
     */
    private WebTestClient asSuperAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN"),
                new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private static ModerationDecisionDto approvedDecision() {
        return new ModerationDecisionDto(
                42L, "alice", "user-removal", "spammer@example.com",
                "ban evasion", "approved", "mod1", "admin1",
                Instant.parse("2024-01-01T00:00:00Z"), "default");
    }

    // ── Test cases ──────────────────────────────────────────────────────────────

    /**
     * No credentials → Spring Security's resource-server filter emits 401 before the
     * controller is ever reached; the federation client must never be called.
     */
    @Test
    void anonymous_isUnauthorized() {
        web.post().uri("/bff/admin/moderation/42/decide?approve=true")
                .exchange()
                .expectStatus().isUnauthorized();

        verify(federation, never()).decide(anyLong(), anyBoolean());
    }

    /**
     * A plain authenticated user (ROLE_USER only) must receive 403 — the
     * {@code /bff/admin/**} path rule and the {@code @PreAuthorize("hasRole('ADMIN')")}
     * gate both deny, and the federation client must never be called.
     */
    @Test
    void roleUser_isForbidden() {
        asUser().post().uri("/bff/admin/moderation/42/decide?approve=true")
                .exchange()
                .expectStatus().isForbidden();

        verify(federation, never()).decide(anyLong(), anyBoolean());
    }

    /**
     * ROLE_ADMIN is the minimum required role. The federation client must be called
     * with the correct appeal id and approve flag, and the returned DTO must be
     * propagated as the 200 response body.
     */
    @Test
    void admin_approve_callsFederationAndReturns200() {
        when(federation.decide(42L, true)).thenReturn(Mono.just(approvedDecision()));
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());

        asAdmin().post().uri("/bff/admin/moderation/42/decide?approve=true")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo(42)
                .jsonPath("$.status").isEqualTo("approved")
                .jsonPath("$.adminDecider").isEqualTo("admin1");

        verify(federation).decide(eq(42L), eq(true));
    }

    /**
     * Deny path: approve=false must be forwarded faithfully to the federation client.
     */
    @Test
    void admin_deny_callsFederationWithFalse() {
        ModerationDecisionDto denied = new ModerationDecisionDto(
                7L, "bob", "instance-block", "bad.example.com",
                "spam", "denied", "mod2", "admin1",
                Instant.parse("2024-01-02T00:00:00Z"), "default");
        when(federation.decide(7L, false)).thenReturn(Mono.just(denied));
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());

        asAdmin().post().uri("/bff/admin/moderation/7/decide?approve=false")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("denied");

        verify(federation).decide(eq(7L), eq(false));
    }

    /**
     * ROLE_SUPERADMIN satisfies {@code hasRole('ADMIN')} via the role hierarchy
     * ({@code SUPERADMIN > ADMIN} in {@link net.hugmesh.adminbff.config.SecurityConfig}).
     * A superadmin must reach the endpoint and the federation client must be called.
     */
    @Test
    void superadmin_isAllowed() {
        when(federation.decide(99L, true)).thenReturn(Mono.just(approvedDecision()));
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());

        asSuperAdmin().post().uri("/bff/admin/moderation/99/decide?approve=true")
                .exchange()
                .expectStatus().isOk();

        verify(federation).decide(eq(99L), eq(true));
    }

    /**
     * {@code @Positive} on the {@code {id}} path variable rejects zero and negative
     * values with 400 before the proxy call — the federation client must never be
     * contacted.
     */
    @Test
    void negativeId_isBadRequest() {
        asAdmin().post().uri("/bff/admin/moderation/-1/decide?approve=true")
                .exchange()
                .expectStatus().isBadRequest();

        verify(federation, never()).decide(anyLong(), anyBoolean());
    }

    /**
     * Zero is also not @Positive — the @Positive constraint rejects id=0.
     */
    @Test
    void zeroId_isBadRequest() {
        asAdmin().post().uri("/bff/admin/moderation/0/decide?approve=true")
                .exchange()
                .expectStatus().isBadRequest();

        verify(federation, never()).decide(anyLong(), anyBoolean());
    }

    /**
     * When the federation-api client throws a runtime exception (e.g. connection
     * refused, 5xx from the downstream service), the BFF must surface a clean 502
     * Bad Gateway — never a raw 500 leak — via the {@code onErrorResume} in
     * {@link AdminController#decideModeration}.
     */
    @Test
    void federationApiDown_returns502BadGateway() {
        when(federation.decide(anyLong(), anyBoolean()))
                .thenReturn(Mono.error(new RuntimeException("Connection refused: federation-api:8080")));

        asAdmin().post().uri("/bff/admin/moderation/42/decide?approve=true")
                .exchange()
                .expectStatus().isEqualTo(502)
                .expectBody()
                .jsonPath("$.error").exists();

        verify(federation).decide(eq(42L), eq(true));
    }

    /**
     * An {@link net.hugmesh.commons.web.ApiException} thrown from the client
     * (e.g. a 404 proxied as not-found) must propagate as-is — NOT re-wrapped as 502.
     * The {@code onErrorResume} in the controller only wraps non-ApiException errors.
     */
    @Test
    void federationApiThrowsApiException_propagatesStatusUnchanged() {
        when(federation.decide(anyLong(), anyBoolean()))
                .thenReturn(Mono.error(net.hugmesh.commons.web.ApiException.notFound("appeal 42 not found")));

        asAdmin().post().uri("/bff/admin/moderation/42/decide?approve=true")
                .exchange()
                .expectStatus().isNotFound()
                .expectBody()
                .jsonPath("$.error").isEqualTo("appeal 42 not found");
    }
}
