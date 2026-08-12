package net.hugmesh.adminbff;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
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
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.adminbff.account.AccountLocalpartRepository;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.locallogin.LocalLoginRateLimiter;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.usage.UsageService;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Two-stage registration / login / me / provision contract, reactive — JSON shapes
 * mirror the reference impl (mock-bff.mjs). A REAL DURABLE {@link AccountStore}
 * (over Liquibase-applied H2) drives the session lifecycle; the broker + usage are
 * mocked.
 *
 * <p>{@code /bff/register/**} and {@code /bff/login} are permitAll (no Casdoor JWT
 * yet). {@code /bff/me/**} and {@code /bff/provision/**} are authenticated —
 * tests attach a {@code mockJwt()} (with the email claim for the production path)
 * to satisfy the filter chain. Each method uses a UNIQUE email/handle so the
 * shared durable store stays order-independent.
 */
@WebFluxTest(controllers = AuthController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class, TestDatabaseConfig.class,
        LocalLoginRateLimiter.class})
class AuthControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }
    @Autowired AccountStore store;

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
            AccountStore store = new AccountStore(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AllowlistRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AccountRowRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.BffSessionRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.NamespaceGrantRepository.class), "admin@hugmesh.systems");
            store.seedAdmins();
            return store;
        }

        /** A2 cookie service in its DARK default (cookie mode off). */
        @Bean net.hugmesh.authcore.config.SessionCookieService sessionCookieService() {
            return new net.hugmesh.authcore.config.SessionCookieService(false, true, null);
        }

        /** The account-takeover-by-collision guard, over the SAME real (Testcontainers)
         *  Postgres the durable {@code AccountStore} bean above uses — so a colliding
         *  localpart is genuinely rejected/collision-checked at the DB, not mocked away. */
        @Bean AccountLocalpartService accountLocalpartService(DatabaseClient db) {
            return new AccountLocalpartService(
                    net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, AccountLocalpartRepository.class));
        }
    }

    @org.junit.jupiter.api.BeforeEach
    void stubStatusAndProfile() {
        // Default: every principal is ACTIVE + the profile forward is a no-op, so the
        // existing session/me shapes are unchanged. The status-specific tests override.
        when(suspensions.statusFor(anyString()))
                .thenReturn(Mono.just(net.hugmesh.authcore.account.AccountStatus.active()));
        when(profiles.forward(anyString(), any(), any())).thenReturn(Mono.empty());
    }

    private void stubUsage() {
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
    }

    @Test
    void registerGoogle_invited_returnsSessionWithToken() {
        stubUsage();
        web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"admin@hugmesh.systems\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.token").exists()
                .jsonPath("$.id").isEqualTo("google:admin@hugmesh.systems")
                .jsonPath("$.provider").isEqualTo("google")
                .jsonPath("$.roles[0]").isEqualTo("user")
                .jsonPath("$.roles[1]").isEqualTo("admin")
                .jsonPath("$.registrationComplete").isEqualTo(false);
    }

    @Test
    void registerGoogle_notInvited_403WithErrorBody() {
        stubUsage();
        web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"stranger@gmail.com\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("email not invited by an admin");
    }

    @Test
    void registerDiscord_notInvited_403() {
        stubUsage();
        web.post().uri("/bff/register/discord").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"nobody-here\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("discord username not invited by an admin");
    }

    /**
     * Gap-2 close (adversarial round-1-review finding, HIGH): the mandatory sequential
     * collision case, driven through the REAL {@code POST /bff/register/discord} HTTP
     * endpoint end-to-end (real {@link AuthController}, real durable {@link AccountStore},
     * real {@link AccountLocalpartService} — the {@link Cfg#accountLocalpartService} bean
     * above, over the SAME Testcontainers Postgres this whole class shares — genuinely
     * collision-checked, NOT mocked). {@code "collide!one"} and {@code "collide#one"} are
     * two DIFFERENT discord handles (no {@code @Pattern} restriction on {@code
     * RegisterDiscordRequest#username}, so the punctuation round-trips through invite +
     * register untouched) that BOTH sanitize to the SAME homeserver localpart {@code
     * "collideone"} ({@code ServiceTokenBroker.matrixUser}: lowercase, strip everything
     * outside {@code [a-z0-9._=/-]}). The FIRST registration must succeed; the SECOND —
     * a genuinely different account that would otherwise silently hijack the first's
     * homeserver identity at {@code provision} time — must be rejected 409, exactly the
     * account-takeover-by-collision this whole fix closes.
     */
    @Test
    void registerDiscord_collidingLocalpart_secondRegistrationRejectedWith409() {
        stubUsage();
        store.inviteDiscord("collide!one", "default").block();
        store.inviteDiscord("collide#one", "default").block();

        web.post().uri("/bff/register/discord").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"collide!one\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("discord:collide!one");

        web.post().uri("/bff/register/discord").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"username\":\"collide#one\"}")
                .exchange().expectStatus().isEqualTo(409)
                .expectBody().jsonPath("$.error")
                .value(org.hamcrest.Matchers.allOf(
                        org.hamcrest.Matchers.containsString("collideone"),
                        org.hamcrest.Matchers.containsString("already in use")));

        // The rejected second registration never got a session either — no account
        // silently landed on the first account's already-claimed homeserver identity.
        StepVerifier.create(store.account("discord:collide#one"))
                .assertNext(a -> assertThat(a.registrationComplete()).isFalse())
                .verifyComplete();
    }

    @Test
    void login_noAccount_401() {
        stubUsage();
        store.inviteEmail("never-registered@x.com", "default").block();
        web.post().uri("/bff/login").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"never-registered@x.com\",\"provider\":\"google\"}")
                .exchange().expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.error").isEqualTo("no account — register first");
    }

    @Test
    void me_withoutJwt_401FromFilterChain() {
        web.get().uri("/bff/me").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void me_jwtButNoBffSession_401LoginRequired() {
        web.mutateWith(mockJwt()).get().uri("/bff/me").exchange()
                .expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.error").isEqualTo("login required");
    }

    @Test
    void fullFlow_register_me_complete_provision() {
        stubUsage();
        store.inviteEmail("flow@x.com", "default").block();
        // Stage 1: register (permitAll) → opaque BFF session token issued.
        web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"flow@x.com\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.token").exists();

        // The matrix provision endpoint is now @PreAuthorize hasRole('MATRIX').
        // mockJwt() does not run the production authorities converter, so grant
        // ROLE_MATRIX (+ the ROLE_USER floor) explicitly; the email claim still
        // resolves the registered account (prod flow).
        var asFlow = mockJwt()
                .jwt(j -> j.claim("email", "flow@x.com"))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_MATRIX"));

        // The Casdoor-JWT email claim resolves the registered account (prod flow).
        web.mutateWith(asFlow).get().uri("/bff/me").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("google:flow@x.com")
                .jsonPath("$.registrationComplete").isEqualTo(false);

        // Provision before completion is forbidden.
        web.mutateWith(asFlow).post().uri("/bff/provision/matrix").exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("complete registration first");

        // Stage 2: complete.
        web.mutateWith(asFlow).post().uri("/bff/register/complete").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.registrationComplete").isEqualTo(true);

        // Now provision brokers a real token (mocked).
        when(broker.matrixToken(anyString())).thenReturn(Mono.just(
                Map.of("access_token", "mx_tok", "user_id", "@flow:hugmesh.systems")));
        web.mutateWith(asFlow).post().uri("/bff/provision/matrix").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.access_token").isEqualTo("mx_tok")
                .jsonPath("$.user_id").isEqualTo("@flow:hugmesh.systems");

        // /bff/me/namespaces: a non-admin user starts with no grants.
        web.mutateWith(asFlow).get().uri("/bff/me/namespaces").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.namespaces").isArray()
                .jsonPath("$.namespaces").isEmpty();
    }

    @Test
    void provisionMastodon_passesMatrixKeyAndPersistedMastodonFold_toBroker() {
        // 291 wiring (against REAL H2 + the real AccountLocalpartService): /bff/provision/mastodon
        // must (a) guard-key the broker on the Matrix-style username (the suspension row key) and
        // (b) mint under the PERSISTED, coarser Mastodon fold — proven by a DOTTED handle where
        // the two folds DIFFER ("flow.dev" -> Matrix "flow.dev", Mastodon "flow_dev"). A re-fold
        // of the username here would (wrongly) pass "flow_dev" as BOTH; reading the persisted
        // value keeps the row key intact.
        stubUsage();
        store.inviteEmail("flow.dev@x.com", "default").block();
        web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"flow.dev@x.com\"}")
                .exchange().expectStatus().isOk();

        var asFlow = mockJwt()
                .jwt(j -> j.claim("email", "flow.dev@x.com"))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_MASTODON"));

        web.mutateWith(asFlow).post().uri("/bff/register/complete").exchange()
                .expectStatus().isOk();

        when(broker.mastodonToken(anyString(), anyString()))
                .thenReturn(Mono.just(Map.of("access_token", "mstdn_tok")));
        web.mutateWith(asFlow).post().uri("/bff/provision/mastodon").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.access_token").isEqualTo("mstdn_tok");

        // Row key = the Matrix-style username; homeserver localpart = the persisted Mastodon fold.
        org.mockito.Mockito.verify(broker).mastodonToken("flow.dev", "flow_dev");
    }

    @Test
    void provision_rejectsReservedUsername_withoutCallingBroker() {
        stubUsage();
        // A discord handle "support" → matrix localpart "support", which is a
        // reserved app prefix. Even after a completed registration the broker
        // must never be asked to mint a real homeserver account for it.
        // (NOT "admin": this class's shared durable store already has a
        // google:admin@hugmesh.systems row whose localpart is ALSO "admin" —
        // reusing that literal here would trip the NEW account-localpart-collision
        // guard instead of exercising the reserved-username rejection this test is
        // actually about. This account is created directly via AccountStore
        // (bypassing AuthController entirely), so its localpart column starts
        // unset — this specifically exercises provision()'s self-heal-then-check
        // path, not the registration-time persistLocalpart path.)
        store.inviteDiscord("support", "default").block();
        store.ensureAccount("discord", "support")
                .flatMap(store::markComplete).block();

        var asAdminHandle = mockJwt()
                .jwt(j -> j.claim("preferred_username", "support"))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_MATRIX"));
        web.mutateWith(asAdminHandle).post().uri("/bff/provision/matrix").exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.error")
                .value(org.hamcrest.Matchers.containsString("reserved"));
        // Broker was never invoked (no matrixToken stub needed).
        org.mockito.Mockito.verify(broker, org.mockito.Mockito.never())
                .matrixToken(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void loginAfterRegister_succeeds() {
        stubUsage();
        store.inviteEmail("login@x.com", "default").block();
        web.post().uri("/bff/register/google").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"login@x.com\"}")
                .exchange().expectStatus().isOk();
        web.post().uri("/bff/login").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"login@x.com\",\"provider\":\"google\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.token").exists()
                .jsonPath("$.id").isEqualTo("google:login@x.com");
    }
}
