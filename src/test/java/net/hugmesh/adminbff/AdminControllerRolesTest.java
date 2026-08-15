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
import net.hugmesh.adminbff.iso.IsoRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.urlregistry.UrlRegistryService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.username.UsernameGate;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.longThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * FEAT-07 — standalone Casdoor role grant/revoke endpoints.
 *
 * <ul>
 *   <li>ROLE gating: plain USER → 403; ADMIN → 200; SUPERADMIN → 200.</li>
 *   <li>Valid role → casdoor.addUserToRole / removeUserFromRole called with correct args.</li>
 *   <li>Invalid roleName (ROLE_SUPERADMIN, service roles) → 400 from @Pattern.</li>
 * </ul>
 */
@WebFluxTest(controllers = AdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class})
class AdminControllerRolesTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean RouteAccessService routeAccess;
    @MockitoBean UrlRegistryService urlRegistry;
    @MockitoBean IsoRepository isoRepo;
    @MockitoBean AccountStore store;
    @MockitoBean UsageService usage;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean DomainLockService domainLocks;
    @MockitoBean net.hugmesh.adminbff.federation.FederationApiClient federation;
    @MockitoBean CasdoorAdminClient casdoor;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;
    @MockitoBean UsernameGate usernameGate;
    @MockitoBean net.hugmesh.adminbff.capability.DomainCapabilityService domainCapabilities;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    /**
     * The {@code roles} JWT CLAIM matters here, not just the Spring authorities:
     * {@code PrincipalDomain.resolve} derives {@code superadmin()} via
     * {@code Roles.isSuperadmin(Jwt)}, which reads the raw claim. Without it the
     * external-client gate would treat a superadmin as a scoped admin.
     */
    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.claim("roles", java.util.List.of("superadmin")))
                .authorities(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    @Test
    void grantRole_anonymous_isUnauthorized() {
        web.post().uri("/bff/admin/roles/ROLE_MATRIX/alice").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void grantRole_asUser_isForbidden() {
        asUser().post().uri("/bff/admin/roles/ROLE_MATRIX/alice").exchange().expectStatus().isForbidden();
    }

    @Test
    void grantRole_asAdmin_callsCasdoorAndReturns200() {
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(eq("ROLE_MATRIX"), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().post().uri("/bff/admin/roles/ROLE_MATRIX/alice")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.granted").isEqualTo("ROLE_MATRIX")
                .jsonPath("$.user").isEqualTo("alice");

        verify(casdoor).addUserToRole("ROLE_MATRIX", "hugmesh/alice");
    }

    @Test
    void grantRole_asSuperadmin_isAllowed() {
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asSuperadmin().post().uri("/bff/admin/roles/ROLE_ADMIN/bob")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.granted").isEqualTo("ROLE_ADMIN");
    }

    @Test
    void grantRole_writesSubjectRevocationKey_picksUpNewRoleOnReMint() {
        // Symmetric with revokeRole: granting a role invalidates the grantee's live
        // custody JWT so the NEW role is picked up on the next re-minted token rather
        // than only after the natural TTL (G2 inverse-stale fix).
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().post().uri("/bff/admin/roles/ROLE_GAMES/dave")
                .exchange().expectStatus().isOk();

        verify(revocations).revokeSubject(
                eq("dave"), eq("role-grant"), longThat(ttl -> ttl >= 3600L));
    }

    @Test
    void grantRole_invalidRoleName_isBadRequest() {
        // ROLE_SUPERADMIN and ROLE_GATEWAY are NOT in the grantable set.
        asAdmin().post().uri("/bff/admin/roles/ROLE_SUPERADMIN/alice")
                .exchange().expectStatus().isBadRequest();
        asAdmin().post().uri("/bff/admin/roles/ROLE_GATEWAY/alice")
                .exchange().expectStatus().isBadRequest();
        asAdmin().post().uri("/bff/admin/roles/ROLE_SERVICE/alice")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void revokeRole_anonymous_isUnauthorized() {
        web.delete().uri("/bff/admin/roles/ROLE_MATRIX/alice").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void revokeRole_asUser_isForbidden() {
        asUser().delete().uri("/bff/admin/roles/ROLE_MATRIX/alice").exchange().expectStatus().isForbidden();
    }

    @Test
    void revokeRole_asAdmin_callsCasdoorAndReturns200() {
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.removeUserFromRole(eq("ROLE_GAMES"), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().delete().uri("/bff/admin/roles/ROLE_GAMES/bob")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.revoked").isEqualTo("ROLE_GAMES")
                .jsonPath("$.user").isEqualTo("bob");

        verify(casdoor).removeUserFromRole("ROLE_GAMES", "hugmesh/bob");
    }

    @Test
    void revokeRole_writesSubjectRevocationKey_closesStaleJwtWindow() {
        // Prove that revokeRole triggers a subject: revocation write so a stale custody
        // JWT (which retains the revoked role for up to its natural TTL, ~1 h) is denied
        // at the gateway within the revocation poll cycle rather than expiring naturally.
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.removeUserFromRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().delete().uri("/bff/admin/roles/ROLE_MATRIX/carol")
                .exchange().expectStatus().isOk();

        // subject: key stamped with the grantee's casdoor user id and TTL >= custody JWT lifetime.
        verify(revocations).revokeSubject(
                eq("carol"), eq("role-revoke"), longThat(ttl -> ttl >= 3600L));
    }

    @Test
    void revokeRole_invalidRoleName_isBadRequest() {
        asAdmin().delete().uri("/bff/admin/roles/ROLE_API_API/alice")
                .exchange().expectStatus().isBadRequest();
    }

    // ══════════ external-client capability gate (DomainCapability.EXTERNAL_CLIENT_GRANT) ══════════
    //
    // grantRole is the ONLY assignment path for the two ROLE_*_EXTERNAL_CLIENT roles, so
    // this is where the superadmin switch has to bite. If the gate lived on a bespoke
    // external-client endpoint instead, POSTing the generic /roles/... path would walk
    // straight around it and the superadmin control would be decorative.

    /** Arm the Casdoor write path so a test that reaches it succeeds. */
    private void casdoorWritesSucceed() {
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());
    }

    @Test
    void grantExternalClientRole_capabilityInactive_isForbidden_andNeverWritesCasdoor() {
        when(domainCapabilities.isActive(anyString(),
                eq(net.hugmesh.adminbff.capability.DomainCapability.EXTERNAL_CLIENT_GRANT)))
                .thenReturn(Mono.just(false));

        asAdmin().post().uri("/bff/admin/roles/ROLE_MATRIX_EXTERNAL_CLIENT/alice")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.capability").isEqualTo("external-client-grant")
                .jsonPath("$.role").isEqualTo("ROLE_MATRIX_EXTERNAL_CLIENT");

        verify(casdoor, never()).addUserToRole(anyString(), anyString());
    }

    @Test
    void grantExternalClientRole_capabilityActive_isAllowed() {
        casdoorWritesSucceed();
        when(domainCapabilities.isActive(anyString(),
                eq(net.hugmesh.adminbff.capability.DomainCapability.EXTERNAL_CLIENT_GRANT)))
                .thenReturn(Mono.just(true));

        asAdmin().post().uri("/bff/admin/roles/ROLE_MASTODON_EXTERNAL_CLIENT/alice")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.granted").isEqualTo("ROLE_MASTODON_EXTERNAL_CLIENT");

        verify(casdoor).addUserToRole("ROLE_MASTODON_EXTERNAL_CLIENT", "hugmesh/alice");
    }

    @Test
    void grantNonExternalClientRole_neverConsultsTheCapabilityGate() {
        // The gate is scoped to exactly two roles; every other grantable role must be
        // unaffected (and must not pay for a gate read).
        casdoorWritesSucceed();

        asAdmin().post().uri("/bff/admin/roles/ROLE_MATRIX/alice")
                .exchange().expectStatus().isOk();

        verify(domainCapabilities, never()).isActive(anyString(), anyString());
    }

    @Test
    void grantExternalClientRole_asSuperadmin_bypassesTheGate() {
        // A superadmin owns the switch itself; the grantee can be in any brand, so there
        // is no single gate row that would be the right one to read.
        casdoorWritesSucceed();

        asSuperadmin().post().uri("/bff/admin/roles/ROLE_MATRIX_EXTERNAL_CLIENT/alice")
                .exchange().expectStatus().isOk();

        verify(domainCapabilities, never()).isActive(anyString(), anyString());
    }

    @Test
    void revokeExternalClientRole_isNeverGated() {
        // Taking a capability AWAY must never be blocked by the capability being off —
        // otherwise flipping the switch would strand every already-granted user.
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.removeUserFromRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());

        asAdmin().delete().uri("/bff/admin/roles/ROLE_MATRIX_EXTERNAL_CLIENT/alice")
                .exchange().expectStatus().isOk();

        verify(casdoor).removeUserFromRole("ROLE_MATRIX_EXTERNAL_CLIENT", "hugmesh/alice");
        verify(domainCapabilities, never()).isActive(anyString(), anyString());
    }
}
