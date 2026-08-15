package net.hugmesh.adminbff;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.domainlock.DomainLockService;
import net.hugmesh.adminbff.iso.IsoRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.urlregistry.UrlRegistryService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.username.FederationUsernameClient;
import net.hugmesh.authcore.username.UsernameGate;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Admin allowlist + namespace-access + usage contract and admin gating, reactive.
 * A REAL DURABLE {@link AccountStore} (over Liquibase-applied H2 via
 * TestDatabaseConfig) so the allowlist/grant state round-trips; usage/route/iso
 * are mocked. {@code @PreAuthorize("hasRole('ADMIN')")} is the defence-in-depth
 * re-check — a USER principal is forbidden. The Casdoor write client is absent
 * (casdoor.admin.enabled defaults false) so {@code @Nullable CasdoorAdminClient}
 * resolves to null and the invite still writes the durable allowlist row.
 */
@WebFluxTest(controllers = AdminController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class, TestDatabaseConfig.class})
class AdminControllerAllowlistTest {

    @Autowired ApplicationContext context;
    @Autowired AccountStore store;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean RouteAccessService routeAccess;
    @MockitoBean UrlRegistryService urlRegistry;
    @MockitoBean IsoRepository isoRepo;
    @MockitoBean UsageService usage;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean DomainLockService domainLocks;
    @MockitoBean net.hugmesh.adminbff.federation.FederationApiClient federation;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;
    @MockitoBean net.hugmesh.adminbff.capability.DomainCapabilityService domainCapabilities;

    @TestConfiguration
    static class Cfg {
        @Bean AccountStore accountStore(DatabaseClient db) {
            AccountStore store = new AccountStore(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AllowlistRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AccountRowRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.BffSessionRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.NamespaceGrantRepository.class), "admin@hugmesh.net");
            store.seedAdmins();
            return store;
        }

        // Username-derivation gate with the federation client DISABLED (default):
        // the local ReservedNames fast-path is the only check, so a derived
        // reserved username is still hard-rejected, everything else passes.
        @Bean FederationUsernameClient federationUsernameClient() {
            return new FederationUsernameClient(null, false, "X-Internal-Token", null);
        }

        @Bean UsernameGate usernameGate(FederationUsernameClient federation) {
            return new UsernameGate(federation);
        }
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    void allowlist_returnsSeedAdmin() {
        when(usage.record(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.anyString())).thenReturn(reactor.core.publisher.Mono.empty());
        // Seed deterministically AT TEST TIME: the Cfg-bean seedAdmins() runs at
        // bean-creation, racing the allowlist-domain migration (#19), so it can silently
        // no-op. The seed email derives the reserved username "admin", so it must be written
        // via the store (the controller's username gate would 422 it) — exactly as
        // seedAdmins() does. The mockJwt() slice principals carry no issuer claim, so
        // PrincipalDomain resolves them to the NO_DOMAIN sentinel scope (Roles read JWT
        // claims, NOT Spring authorities); invite into that same scope the admin reads from.
        store.inviteEmail("admin@hugmesh.net",
                net.hugmesh.commons.security.PrincipalDomain.NO_DOMAIN).block();
        asAdmin().get().uri("/bff/admin/allowlist").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.emails").value(org.hamcrest.Matchers.hasItem("admin@hugmesh.net"))
                .jsonPath("$.discord").isArray();
    }

    @Test
    void allowlist_forbiddenForNonAdmin() {
        asUser().get().uri("/bff/admin/allowlist").exchange().expectStatus().isForbidden();
    }

    @Test
    void invite_addsEmailAndDiscord() {
        when(usage.record(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.anyString())).thenReturn(reactor.core.publisher.Mono.empty());
        asAdmin().post().uri("/bff/admin/allowlist").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"new@gmail.com\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.emails").value(org.hamcrest.Matchers.hasItem("new@gmail.com"));
        asAdmin().post().uri("/bff/admin/allowlist").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"discord\":\"cooluser\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.discord").value(org.hamcrest.Matchers.hasItem("cooluser"));
    }

    @Test
    void invite_422WhenDerivedUsernameIsReserved() {
        // admin@gmail.com derives the Casdoor username 'admin' — a reserved label
        // — so the API-layer username gate refuses the invite (422) before any
        // allowlist/Casdoor write.
        asAdmin().post().uri("/bff/admin/allowlist").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"admin@gmail.com\"}")
                .exchange().expectStatus().isEqualTo(org.springframework.http.HttpStatus.UNPROCESSABLE_CONTENT)
                .expectBody()
                .jsonPath("$.reason").isEqualTo("reserved")
                .jsonPath("$.candidate").isEqualTo("admin");
    }

    @Test
    void invite_422WhenDiscordHandleIsReserved() {
        // A Discord handle that is itself a reserved label (e.g. 'vault') is
        // rejected too — the handle is used verbatim as the Casdoor username.
        asAdmin().post().uri("/bff/admin/allowlist").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"discord\":\"vault\"}")
                .exchange().expectStatus().isEqualTo(org.springframework.http.HttpStatus.UNPROCESSABLE_CONTENT)
                .expectBody().jsonPath("$.reason").isEqualTo("reserved");
    }

    /**
     * The canonical revision 7-9 labels — {@code hmdm}/{@code attest} (Headwind MDM +
     * AttestationServer superadmin-gateway route prefixes) and the Character Forge
     * track's {@code character-forge}/{@code games-character-forge}/
     * {@code games-shadows-of-the-net} — are enforced AT RUNTIME by the pinned
     * auth-core (2.4.1): a Discord handle equal to any of them is refused 422 by the
     * same API-layer username gate that rejects the older labels, through the REAL
     * controller + UsernameGate + auth-core ReservedNames path. Named explicitly so
     * a pin downgrade to a pre-revision-9 auth-core fails THIS test with the
     * missing label's name.
     */
    @ParameterizedTest
    @ValueSource(strings = {"hmdm", "attest", "character-forge",
            "games-character-forge", "games-shadows-of-the-net"})
    void invite_422WhenDiscordHandleIsACanonicalRev7To9Label(String reserved) {
        asAdmin().post().uri("/bff/admin/allowlist").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"discord\":\"" + reserved + "\"}")
                .exchange().expectStatus().isEqualTo(org.springframework.http.HttpStatus.UNPROCESSABLE_CONTENT)
                .expectBody()
                .jsonPath("$.reason").isEqualTo("reserved")
                .jsonPath("$.candidate").isEqualTo(reserved);
    }

    @Test
    void uninvite_writesSubjectRevocationKey_forBothHandles() {
        when(usage.record(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.anyString())).thenReturn(reactor.core.publisher.Mono.empty());
        when(revocations.revokeSubject(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyLong()))
                .thenReturn(reactor.core.publisher.Mono.empty());
        // Uninviting/disabling an account must invalidate any live custody JWT for it — a
        // bare account-disable (no accompanying ban) otherwise survives to the natural ~1h
        // TTL. The subject is the Casdoor username (usernameOf), reason "account-disable",
        // TTL = custody-JWT lifetime — fired for BOTH the email- and discord-derived
        // identities, and independent of whether the Casdoor write client is configured
        // (it is null here, so casdoorDisable no-ops but the revocation still runs).
        // Distinct handles so the two derived Casdoor usernames differ (alice vs bob) —
        // otherwise a single eq() matches both invocations.
        asAdmin().method(org.springframework.http.HttpMethod.DELETE).uri("/bff/admin/allowlist")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"alice@gmail.com\",\"discord\":\"bob\"}")
                .exchange().expectStatus().isOk();
        org.mockito.Mockito.verify(revocations).revokeSubject(
                org.mockito.ArgumentMatchers.eq(net.hugmesh.authcore.casdoor.CasdoorAdminClient
                        .usernameOf("google", "alice@gmail.com")),
                org.mockito.ArgumentMatchers.eq("account-disable"),
                org.mockito.ArgumentMatchers.eq(3_600L));
        org.mockito.Mockito.verify(revocations).revokeSubject(
                org.mockito.ArgumentMatchers.eq(net.hugmesh.authcore.casdoor.CasdoorAdminClient
                        .usernameOf("discord", "bob")),
                org.mockito.ArgumentMatchers.eq("account-disable"),
                org.mockito.ArgumentMatchers.eq(3_600L));
    }

    @Test
    void namespaceAccess_grantThenList() {
        when(usage.record(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.anyString())).thenReturn(reactor.core.publisher.Mono.empty());
        asAdmin().get().uri("/bff/admin/namespace-access").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.namespaces[0]").isEqualTo("hugmesh-pki")
                .jsonPath("$.grants").isArray();

        asAdmin().post().uri("/bff/admin/namespace-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"user\":\"bob\",\"namespace\":\"observability\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.grants[0].user").isEqualTo("bob")
                .jsonPath("$.grants[0].namespaces[0]").isEqualTo("observability");
    }

    @Test
    void namespaceGrant_400ForInvalidNamespace() {
        asAdmin().post().uri("/bff/admin/namespace-access").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"user\":\"bob\",\"namespace\":\"nope\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error").isEqualTo("user + valid namespace required");
    }

    @Test
    void usage_delegatesToService() {
        when(usage.aggregate()).thenReturn(reactor.core.publisher.Mono.just(
                java.util.Map.of("byModule", java.util.List.of(), "byAction", java.util.List.of(),
                        "activeUsers", 0, "totalEvents", 0)));
        asAdmin().get().uri("/bff/admin/usage").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.totalEvents").isEqualTo(0);
    }
}
