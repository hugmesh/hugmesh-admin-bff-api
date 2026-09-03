package net.hugmesh.adminbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.account.AccountLocalpartRepository;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.account.RegistrationDomainResolver;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.locallogin.LocalLoginRateLimiter;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.account.AccountRowRepository;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.account.AllowlistRepository;
import net.hugmesh.authcore.account.BffSessionRepository;
import net.hugmesh.authcore.account.NamespaceGrantRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * REGISTRATION-GATE DOMAIN SCOPE (hugmesh-auth-core issue #1) — the HTTP-boundary proof that
 * an invite stamped with one brand's domain does not admit that identifier on another brand.
 *
 * <p><b>What was broken.</b> {@code AdminController.invite} has stamped the acting admin's
 * {@code PrincipalDomain} onto the {@code allowlist} row since changeset 220, but the GATE read
 * was {@code AccountStore.isEmailInvited(email)} — "invited in ANY domain". So an invite brand
 * A's admin issued also let that identifier register on brand B. auth-core 2.5.0 added the
 * domain-scoped overloads; this repo now passes them a SERVER-DERIVED requesting domain (see
 * {@link RegistrationDomainResolver}).
 *
 * <p><b>Why these tests genuinely fail on the old behaviour</b> rather than merely passing on
 * the new: the allowlist rows are seeded through the PRODUCTION {@code AccountStore.inviteEmail}
 * / {@code inviteDiscord} into a REAL Postgres, and the assertions are on the HTTP status of the
 * real {@code POST /bff/register/**}. Reverting either call site to the unscoped 1-arg overload
 * turns every {@code isForbidden()} below into a 200 with a session token — the exact hole.
 * {@link #crossBrandInvite_rowExists_butDoesNotAdmit()} additionally asserts the brand-A row is
 * really there, so a deny can never be passed off by a missing invite.
 *
 * <p>This deployment is pinned to {@code brand-b} via {@code app.tenancy.registration-domain},
 * the per-deployment shape a brand-dedicated admin-bff uses; the token-derived and
 * fail-closed shapes are pinned in {@code RegistrationDomainResolverTest}. The untenanted
 * single-tenant path (no pin, rows stamped {@code "default"}) stays covered by
 * {@link AuthControllerTest#registerGoogle_invited_returnsSessionWithToken()}, which is the
 * regression guard that this fix did not change single-tenant behaviour.
 */
@WebFluxTest(controllers = AuthController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class,
        RegistrationDomainResolver.class, TestDatabaseConfig.class, LocalLoginRateLimiter.class})
@TestPropertySource(properties = "app.tenancy.registration-domain=brand-b")
class AuthControllerRegistrationDomainScopeTest {

    /** The brand this admin-bff serves. Every invite that admits must carry THIS domain. */
    private static final String THIS_BRAND = "brand-b";
    /** A sibling brand on the same mesh whose invites must never admit here. */
    private static final String OTHER_BRAND = "brand-a";

    @Autowired ApplicationContext context;
    @Autowired AccountStore store;

    WebTestClient web;

    @MockitoBean ServiceTokenBroker broker;
    @MockitoBean UsageService usage;
    @MockitoBean net.hugmesh.adminbff.suspension.SuspensionService suspensions;
    @MockitoBean net.hugmesh.adminbff.profile.ProfileForwarder profiles;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaChallengeService mfaChallenge;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @TestConfiguration
    static class Cfg {
        @Bean AccountStore accountStore(DatabaseClient db) {
            AccountStore store = new AccountStore(
                    R2dbcRepos.of(db, AllowlistRepository.class),
                    R2dbcRepos.of(db, AccountRowRepository.class),
                    R2dbcRepos.of(db, BffSessionRepository.class),
                    R2dbcRepos.of(db, NamespaceGrantRepository.class),
                    "admin@hugmesh.net");
            store.seedAdmins();
            return store;
        }

        @Bean net.hugmesh.authcore.config.SessionCookieService sessionCookieService() {
            return new net.hugmesh.authcore.config.SessionCookieService(false, true, null);
        }

        @Bean AccountLocalpartService accountLocalpartService(DatabaseClient db) {
            return new AccountLocalpartService(R2dbcRepos.of(db, AccountLocalpartRepository.class));
        }
    }

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(suspensions.statusFor(anyString()))
                .thenReturn(Mono.just(net.hugmesh.authcore.account.AccountStatus.active()));
        when(profiles.forward(anyString(), any(), any())).thenReturn(Mono.empty());
    }

    private WebTestClient.ResponseSpec registerGoogle(String email) {
        return web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + email + "\"}").exchange();
    }

    private WebTestClient.ResponseSpec registerDiscord(String handle) {
        return web.post().uri("/bff/register/discord").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"" + handle + "\"}").exchange();
    }

    // ── an entry for domain A does NOT admit the same identifier on domain B ──
    @Test
    void crossBrandInvite_rowExists_butDoesNotAdmit() {
        String email = "cross-brand@example.test";
        store.inviteEmail(email, OTHER_BRAND).block();

        // The invite genuinely EXISTS — brand A's admin can see it. The refusal below is
        // therefore the domain predicate, not a missing row.
        assertThat(store.allowedEmails(OTHER_BRAND).collectList().block()).contains(email);
        assertThat(store.allowedEmails(THIS_BRAND).collectList().block()).doesNotContain(email);

        registerGoogle(email).expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("email not invited by an admin");
    }

    @Test
    void crossBrandDiscordInvite_doesNotAdmit() {
        String handle = "cross-brand-discord";
        store.inviteDiscord(handle, OTHER_BRAND).block();

        assertThat(store.allowedDiscord(OTHER_BRAND).collectList().block()).contains(handle);

        registerDiscord(handle).expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("discord username not invited by an admin");
    }

    // ── the intended domain still admits ───────────────────────────────
    @Test
    void thisBrandInvite_admits() {
        String email = "same-brand@example.test";
        store.inviteEmail(email, THIS_BRAND).block();

        registerGoogle(email).expectStatus().isOk()
                .expectBody()
                .jsonPath("$.token").exists()
                .jsonPath("$.id").isEqualTo("google:" + email)
                .jsonPath("$.provider").isEqualTo("google")
                .jsonPath("$.registrationComplete").isEqualTo(false);
    }

    @Test
    void thisBrandDiscordInvite_admits() {
        String handle = "same-brand-discord";
        store.inviteDiscord(handle, THIS_BRAND).block();

        registerDiscord(handle).expectStatus().isOk()
                .expectBody()
                .jsonPath("$.token").exists()
                .jsonPath("$.id").isEqualTo("discord:" + handle)
                .jsonPath("$.provider").isEqualTo("discord");
    }

    /**
     * The two halves on ONE identifier, which is the issue's own wording: the same address
     * invited on brand A is refused here, and starts working the moment brand B's own admin
     * invites it. Self-contained, so it does not depend on any other method's ordering.
     */
    @Test
    void sameIdentifier_refusedForOtherBrand_thenAdmittedOnceThisBrandInvites() {
        String email = "both-brands@example.test";
        store.inviteEmail(email, OTHER_BRAND).block();
        registerGoogle(email).expectStatus().isForbidden();

        store.inviteEmail(email, THIS_BRAND).block();
        registerGoogle(email).expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("google:" + email);
    }
}
