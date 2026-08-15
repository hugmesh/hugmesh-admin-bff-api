package net.hugmesh.adminbff;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.domainlock.DomainLock;
import net.hugmesh.adminbff.domainlock.DomainLockService;
import net.hugmesh.adminbff.iso.IsoRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.suspension.AccessSuspension;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.urlregistry.UrlRegistryService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.username.UsernameGate;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The admin access-role suspension endpoints: ADMIN gating (non-admin → 403), the
 * write/clear delegation to {@link SuspensionService} (the endpoints only touch the
 * desired-state + reconcile, never Casdoor/homeserver directly), and the
 * {@code role} path-variable @Pattern validation.
 */
@WebFluxTest(controllers = AdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class})
class AdminControllerAccessRolesTest {

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

    private static AccessSuspension sample() {
        return new AccessSuspension("id-1", "hugmesh/alice", "alice",
                AccessSuspension.ROLE_MATRIX, "active", Instant.now(), null, false,
                "pending", "abuse", "admin", "default");
    }

    /** A TIMED ROLE_MESH suspension — the mesh half of the vocabulary (changeset 330).
     *  Timed rather than permanent because the auto-restore at TTL is precisely what the
     *  old hand-strip-the-Casdoor-role workaround could not give a mesh ban. */
    private static AccessSuspension meshSample() {
        return new AccessSuspension("id-2", "hugmesh/mallory", "mallory",
                AccessSuspension.ROLE_MESH, "active", Instant.now(),
                Instant.now().plusSeconds(86400), true,
                "pending", "mesh-abuse", "admin", "default");
    }

    private static DomainLock lockSample() {
        return new DomainLock("dl-1", "hugmesh/alice", "alice",
                DomainLock.ROLE_MASTODON_DOMAINLOCKED, "active", Instant.now(),
                "pending", "spam-federation", "admin", "default");
    }

    @Test
    void suspend_asAdmin_writesDesiredStateAndReturnsList() {
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(suspensions.suspend(eq("ROLE_MATRIX"), eq("alice"), any(), any(), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(sample()));
        when(suspensions.listActive(any(PrincipalDomain.class))).thenReturn(Flux.just(sample()));

        asAdmin().post().uri("/bff/admin/access-roles/ROLE_MATRIX/alice")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"ttlSeconds\":3600,\"reason\":\"abuse\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.suspended.role").isEqualTo("ROLE_MATRIX")
                .jsonPath("$.suspensions[0].localpart").isEqualTo("alice");

        verify(suspensions).suspend(eq("ROLE_MATRIX"), eq("alice"), eq(3600L), eq("abuse"), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void suspend_permanent_noBody_passesNullTtl() {
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(suspensions.suspend(eq("ROLE_MASTODON"), eq("bob"), any(), any(), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(sample()));
        when(suspensions.listActive(any(PrincipalDomain.class))).thenReturn(Flux.just(sample()));

        asAdmin().post().uri("/bff/admin/access-roles/ROLE_MASTODON/bob")
                .exchange().expectStatus().isOk();

        // No body → permanent suspension (null ttl).
        verify(suspensions).suspend(eq("ROLE_MASTODON"), eq("bob"), eq(null), any(), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void clear_asAdmin_clearsDesiredState() {
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        // The direct admin lift-ban endpoint uses clearByHandle (localpart-normalized),
        // NOT the exact-string clear(): an admin lifting a ban may type a different
        // string form of the user's identity than whatever the ban was originally set
        // with, and clearByHandle is the only path that still finds it.
        when(suspensions.clearByHandle(eq("ROLE_MATRIX"), eq("alice"), anyString(), any(PrincipalDomain.class))).thenReturn(Mono.just(1L));
        when(suspensions.listActive(any(PrincipalDomain.class))).thenReturn(Flux.empty());

        asAdmin().delete().uri("/bff/admin/access-roles/ROLE_MATRIX/alice")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.suspensions").isArray();

        verify(suspensions).clearByHandle(eq("ROLE_MATRIX"), eq("alice"), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void suspend_asUser_isForbidden_andNeverWrites() {
        asUser().post().uri("/bff/admin/access-roles/ROLE_MATRIX/alice")
                .exchange().expectStatus().isForbidden();
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any(), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void suspend_roleMesh_isAccepted_andWritesDesiredState() {
        // ROLE_MESH is a first-class member of the closed suspension vocabulary
        // (changeset 330 + the ROLE_PATTERN widening): a mesh abuser is banned through the
        // SAME desired-state endpoint as a Matrix/Mastodon one, so the ban gets an audit
        // row, a TTL and a restore path instead of an operator hand-stripping the Casdoor
        // role. Before the widening this path variable was a 400.
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(suspensions.suspend(eq("ROLE_MESH"), eq("mallory"), any(), any(), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(meshSample()));
        when(suspensions.listActive(any(PrincipalDomain.class))).thenReturn(Flux.just(meshSample()));

        asAdmin().post().uri("/bff/admin/access-roles/ROLE_MESH/mallory")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"ttlSeconds\":86400,\"reason\":\"mesh-abuse\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.suspended.role").isEqualTo("ROLE_MESH")
                .jsonPath("$.suspensions[0].localpart").isEqualTo("mallory");

        // A TEMP ban (the case that was previously impossible for mesh at all) — the TTL
        // reaches the service, which is what arms the expiry action's auto-restore.
        verify(suspensions).suspend(eq("ROLE_MESH"), eq("mallory"), eq(86400L), eq("mesh-abuse"),
                anyString(), any(PrincipalDomain.class));
    }

    @Test
    void clear_roleMesh_liftsTheBan() {
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(suspensions.clearByHandle(eq("ROLE_MESH"), eq("mallory"), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(1L));
        when(suspensions.listActive(any(PrincipalDomain.class))).thenReturn(Flux.empty());

        asAdmin().delete().uri("/bff/admin/access-roles/ROLE_MESH/mallory")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.suspensions").isArray();

        verify(suspensions).clearByHandle(eq("ROLE_MESH"), eq("mallory"), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void suspend_invalidRolePathVar_isBadRequest() {
        asAdmin().post().uri("/bff/admin/access-roles/ROLE_BOGUS/alice")
                .exchange().expectStatus().isBadRequest();
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any(), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void suspend_negativeTtl_isBadRequest_andNeverWrites() {
        // @Positive on SuspensionRequest.ttlSeconds rejects a non-positive TTL.
        asAdmin().post().uri("/bff/admin/access-roles/ROLE_MATRIX/alice")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"ttlSeconds\":-5}")
                .exchange().expectStatus().isBadRequest();
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any(), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void list_asAdmin_returnsActiveSuspensions() {
        when(suspensions.listActive(any(PrincipalDomain.class))).thenReturn(Flux.just(sample()));
        asAdmin().get().uri("/bff/admin/access-roles")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.suspensions[0].casdoorUser").isEqualTo("hugmesh/alice");
    }

    // ── Domain-lock (force local-only) endpoints ───────────────────────
    @Test
    void domainLock_asAdmin_writesDesiredStateAndReturnsList() {
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(domainLocks.lock(eq("ROLE_MASTODON_DOMAINLOCKED"), eq("alice"), any(), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(lockSample()));
        when(domainLocks.listActive(any(PrincipalDomain.class))).thenReturn(Flux.just(lockSample()));

        asAdmin().post().uri("/bff/admin/domain-lock/ROLE_MASTODON_DOMAINLOCKED/alice")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"spam-federation\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.locked.role").isEqualTo("ROLE_MASTODON_DOMAINLOCKED")
                .jsonPath("$.domainLocks[0].localpart").isEqualTo("alice");

        verify(domainLocks).lock(eq("ROLE_MASTODON_DOMAINLOCKED"), eq("alice"), eq("spam-federation"), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void domainLock_noBody_passesNullReason() {
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(domainLocks.lock(eq("ROLE_MATRIX_DOMAINLOCKED"), eq("bob"), any(), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(lockSample()));
        when(domainLocks.listActive(any(PrincipalDomain.class))).thenReturn(Flux.just(lockSample()));

        asAdmin().post().uri("/bff/admin/domain-lock/ROLE_MATRIX_DOMAINLOCKED/bob")
                .exchange().expectStatus().isOk();

        verify(domainLocks).lock(eq("ROLE_MATRIX_DOMAINLOCKED"), eq("bob"), eq(null), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void domainUnlock_asAdmin_clearsDesiredState() {
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(domainLocks.unlock(eq("ROLE_MASTODON_DOMAINLOCKED"), eq("alice"), anyString(), any(PrincipalDomain.class)))
                .thenReturn(Mono.empty());
        when(domainLocks.listActive(any(PrincipalDomain.class))).thenReturn(Flux.empty());

        asAdmin().delete().uri("/bff/admin/domain-lock/ROLE_MASTODON_DOMAINLOCKED/alice")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.domainLocks").isArray();

        verify(domainLocks).unlock(eq("ROLE_MASTODON_DOMAINLOCKED"), eq("alice"), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void domainLock_asUser_isForbidden_andNeverWrites() {
        asUser().post().uri("/bff/admin/domain-lock/ROLE_MASTODON_DOMAINLOCKED/alice")
                .exchange().expectStatus().isForbidden();
        verify(domainLocks, never()).lock(anyString(), anyString(), any(), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void domainLock_invalidRolePathVar_isBadRequest_andNeverWrites() {
        // The closed domain-locked vocabulary is SEPARATE from the suspension roles —
        // a plain ROLE_MASTODON (a suspension role) is NOT a valid domain-lock role.
        asAdmin().post().uri("/bff/admin/domain-lock/ROLE_MASTODON/alice")
                .exchange().expectStatus().isBadRequest();
        verify(domainLocks, never()).lock(anyString(), anyString(), any(), anyString(), any(PrincipalDomain.class));
    }

    @Test
    void domainLock_list_asAdmin_returnsActiveLocks() {
        when(domainLocks.listActive(any(PrincipalDomain.class))).thenReturn(Flux.just(lockSample()));
        asAdmin().get().uri("/bff/admin/domain-lock")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.domainLocks[0].casdoorUser").isEqualTo("hugmesh/alice");
    }
}
