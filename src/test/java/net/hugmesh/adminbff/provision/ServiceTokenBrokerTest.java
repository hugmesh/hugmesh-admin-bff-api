package net.hugmesh.adminbff.provision;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.suspension.SuspensionService;

import java.util.concurrent.atomic.AtomicInteger;

import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Guards the Boot-4 JSON decode path of the homeserver token broker.
 *
 * <p>Before the Boot-4 fix the broker decoded responses with
 * {@code bodyToMono(com.fasterxml.jackson.databind.JsonNode.class)} — a Jackson-2
 * type the Boot-4 reactive WebFlux codec (Jackson 3 / tools.jackson) cannot
 * decode, throwing a {@code CodecException} so EVERY Matrix/Mastodon token mint
 * failed at runtime. It was silent because the controller tests
 * {@code @MockitoBean} this broker rather than exercising its real HTTP decode.
 *
 * <p>These tests stub the homeserver exchange and drive the public
 * {@code matrixToken}/{@code mastodonToken} flows end-to-end through the real
 * codec, so a regression to a codec-incompatible decode fails fast here.
 */
class ServiceTokenBrokerTest {

    /** An exchange that answers every request with the given JSON body (200). */
    private static ExchangeFunction jsonStub(String body) {
        return request -> Mono.just(ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .body(body)
                .build());
    }

    private static ServiceTokenBroker brokerFor(String responseBody) {
        return brokerFor(jsonStub(responseBody));
    }

    private static ServiceTokenBroker brokerFor(ExchangeFunction exchange) {
        WebClient hs = WebClient.builder().exchangeFunction(exchange).build();
        SuspensionService suspensions = mock(SuspensionService.class);
        when(suspensions.isLocalpartSuspended(any(), any()))
                .thenReturn(Mono.just(false));
        HsTokenRegistry hsTokens = mock(HsTokenRegistry.class);
        when(hsTokens.recordBrokered(any(), any(), any()))
                .thenReturn(Mono.empty());
        return new ServiceTokenBroker(hs, hs, "svc-pw", suspensions, hsTokens);
    }

    private static ClientResponse json(HttpStatus status, String body) {
        return ClientResponse.create(status)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .body(body)
                .build();
    }

    @Test
    void mastodonToken_suspensionGuard_keysOnMatrixStyleUsername_notFoldedLocalpart() {
        // Regression for the localpart-key mismatch: SuspensionService stores every role's
        // rows (incl. ROLE_MASTODON) under the matrix-style localpart (matrixUser, keeps
        // '.'/'-'), but the mastodon mint used to guard on mastodonLocalpart(username) which
        // folds those to '_' -> the guard queried a string the row was never stored under ->
        // a MASTODON-suspended user re-minted. The guard must query the incoming matrix-style
        // username (the row key), not the folded form.
        WebClient hs = WebClient.builder()
                .exchangeFunction(jsonStub("{\"access_token\":\"must-not-be-minted\"}")).build();
        SuspensionService suspensions = mock(SuspensionService.class);
        // Suspended under the MATRIX-style key 'alice.bob'; NOT under the folded 'alice_bob'.
        when(suspensions.isLocalpartSuspended("alice.bob",
                net.hugmesh.adminbff.suspension.AccessSuspension.ROLE_MASTODON))
                .thenReturn(Mono.just(true));
        when(suspensions.isLocalpartSuspended("alice_bob",
                net.hugmesh.adminbff.suspension.AccessSuspension.ROLE_MASTODON))
                .thenReturn(Mono.just(false));
        HsTokenRegistry hsTokens = mock(HsTokenRegistry.class);
        when(hsTokens.recordBrokered(any(), any(), any())).thenReturn(Mono.empty());
        ServiceTokenBroker broker = new ServiceTokenBroker(hs, hs, "svc-pw", suspensions, hsTokens);

        // username is the matrix-style localpart (AuthController passes matrixUser(handle)).
        StepVerifier.create(broker.mastodonToken("alice.bob", "alice_bob"))
                .expectErrorSatisfies(e -> assertThat(e).hasMessageContaining("suspended"))
                .verify();
    }

    @Test
    void mastodonToken_usesPassedPersistedLocalpart_notARefoldOfUsername() {
        // 291: the mint keys the homeserver account on the PERSISTED, collision-checked Mastodon
        // localpart passed in — NOT a re-fold of `username`. Pass a DISAMBIGUATED value
        // ("john_doe_deadbeef") that re-folding the matrix-style username "john.doe" would never
        // produce (that folds to "john_doe") and assert the brokered token is recorded under the
        // PASSED value — i.e. the broker read-persisted rather than re-derived.
        var hits = new java.util.HashMap<String, java.util.concurrent.atomic.AtomicInteger>();
        ExchangeFunction ex = routedStub(java.util.Map.of(
                "/api/v1/apps", java.util.List.of(json(HttpStatus.OK, APP_CREDS)),
                "/oauth/token", java.util.List.of(json(HttpStatus.OK,
                        "{\"access_token\":\"mst_ok\",\"token_type\":\"Bearer\"}"))), hits);
        WebClient hs = WebClient.builder().exchangeFunction(ex).build();
        SuspensionService suspensions = mock(SuspensionService.class);
        when(suspensions.isLocalpartSuspended(any(), any())).thenReturn(Mono.just(false));
        HsTokenRegistry hsTokens = mock(HsTokenRegistry.class);
        when(hsTokens.recordBrokered(any(), any(), any())).thenReturn(Mono.empty());
        ServiceTokenBroker broker = new ServiceTokenBroker(hs, hs, "svc-pw", suspensions, hsTokens);

        StepVerifier.create(broker.mastodonToken("john.doe", "john_doe_deadbeef"))
                .assertNext(out -> assertThat(out.get("access_token")).isEqualTo("mst_ok"))
                .verifyComplete();

        ArgumentCaptor<String> localpart = ArgumentCaptor.forClass(String.class);
        verify(hsTokens).recordBrokered(any(), localpart.capture(), eq("mastodon"));
        assertThat(localpart.getValue()).isEqualTo("john_doe_deadbeef");
    }

    @Test
    void matrixToken_decodesTuwunelJson_throughTheBoot4Jackson3Codec() {
        // tuwunel's /register (Synapse-compatible shape) returns an access_token
        // directly (one-shot success).
        ServiceTokenBroker broker = brokerFor(
                "{\"access_token\":\"syt_abc\",\"user_id\":\"@bob:hs\"}");

        StepVerifier.create(broker.matrixToken("bob"))
                .assertNext(out -> {
                    assertThat(out.get("access_token")).isEqualTo("syt_abc");
                    assertThat(out.get("user_id")).isEqualTo("@bob:hs");
                })
                .verifyComplete();
    }

    @Test
    void matrixToken_completesUiaaDummyChallenge_thenReturnsToken() {
        // REGRESSION GUARD (found by live e2e against tuwunel): a spec-compliant Matrix
        // homeserver answers the FIRST /register with HTTP 401 carrying the UIAA challenge
        // ({flows, session}) — the cue to repeat the call with auth.session, NOT an error.
        // The previous .retrieve() raised on that 401, so stage-2 never ran and no real
        // homeserver could be provisioned. With the tolerant register this completes.
        AtomicInteger regCalls = new AtomicInteger();
        ExchangeFunction ex = request -> {
            if (request.url().getPath().endsWith("/register")) {
                return Mono.just(regCalls.incrementAndGet() == 1
                        ? json(HttpStatus.UNAUTHORIZED,
                                "{\"flows\":[{\"stages\":[\"m.login.dummy\"]}],\"session\":\"sess-1\"}")
                        : json(HttpStatus.OK, "{\"access_token\":\"syt_new\",\"user_id\":\"@bob:hs\"}"));
            }
            return Mono.just(json(HttpStatus.OK, "{}"));
        };

        StepVerifier.create(brokerFor(ex).matrixToken("bob"))
                .assertNext(out -> {
                    assertThat(out.get("access_token")).isEqualTo("syt_new");
                    assertThat(out.get("user_id")).isEqualTo("@bob:hs");
                })
                .verifyComplete();
        // Stage-2 must have run — the bug short-circuited at the stage-1 401.
        assertThat(regCalls.get()).isEqualTo(2);
    }

    @Test
    void matrixToken_existingUser_uiaaThenUserInUse_fallsBackToLogin() {
        // Already-registered localpart: stage-2 /register returns HTTP 400 M_USER_IN_USE,
        // which must NOT raise but fall through to password login. The previous .retrieve()
        // raised on the 400 too, so even the login fallback was unreachable.
        AtomicInteger regCalls = new AtomicInteger();
        ExchangeFunction ex = request -> {
            String path = request.url().getPath();
            if (path.endsWith("/register")) {
                return Mono.just(regCalls.incrementAndGet() == 1
                        ? json(HttpStatus.UNAUTHORIZED, "{\"session\":\"sess-1\"}")
                        : json(HttpStatus.BAD_REQUEST, "{\"errcode\":\"M_USER_IN_USE\",\"error\":\"taken\"}"));
            }
            // /login
            return Mono.just(json(HttpStatus.OK, "{\"access_token\":\"syt_login\",\"user_id\":\"@bob:hs\"}"));
        };

        StepVerifier.create(brokerFor(ex).matrixToken("bob"))
                .assertNext(out -> assertThat(out.get("access_token")).isEqualTo("syt_login"))
                .verifyComplete();
    }

    // ── Mastodon mint = the REAL OAuth contract (app creds + grant/register) ─────
    // The old bare {grant_type,username,password} body (mock-bff port) never worked
    // against any real doorkeeper (401 invalid_client). These drive the full flow
    // with a PATH-ROUTED stub: /api/v1/apps → creds; /oauth/token consumed in call
    // order (password grant first, client_credentials second); /api/v1/accounts.

    private static final String APP_CREDS =
            "{\"client_id\":\"cid-1\",\"client_secret\":\"csec-1\"}";

    /** Routes by request path; each path's responses are consumed IN ORDER (last repeats). */
    private static ExchangeFunction routedStub(java.util.Map<String, java.util.List<ClientResponse>> routes,
                                               java.util.Map<String, java.util.concurrent.atomic.AtomicInteger> hits) {
        return request -> {
            String path = request.url().getPath();
            java.util.List<ClientResponse> rs = routes.get(path);
            if (rs == null) {
                return Mono.just(json(HttpStatus.NOT_FOUND, "{\"error\":\"unrouted path " + path + "\"}"));
            }
            int n = hits.computeIfAbsent(path, k -> new java.util.concurrent.atomic.AtomicInteger())
                    .getAndIncrement();
            return Mono.just(rs.get(Math.min(n, rs.size() - 1)));
        };
    }

    private static ServiceTokenBroker routedBroker(java.util.Map<String, java.util.List<ClientResponse>> routes,
                                                   java.util.Map<String, java.util.concurrent.atomic.AtomicInteger> hits) {
        return brokerFor(routedStub(routes, hits));
    }

    @Test
    void mastodonToken_recoversViaPasswordGrant_withAppCreds() {
        var hits = new java.util.HashMap<String, java.util.concurrent.atomic.AtomicInteger>();
        ServiceTokenBroker broker = routedBroker(java.util.Map.of(
                "/api/v1/apps", java.util.List.of(json(HttpStatus.OK, APP_CREDS)),
                "/oauth/token", java.util.List.of(json(HttpStatus.OK,
                        "{\"access_token\":\"mst_xyz\",\"token_type\":\"Bearer\"}"))), hits);

        StepVerifier.create(broker.mastodonToken("bob", "bob"))
                .assertNext(out -> assertThat(out.get("access_token")).isEqualTo("mst_xyz"))
                .verifyComplete();
        assertThat(hits.get("/api/v1/apps").get()).isEqualTo(1);
        assertThat(hits.get("/oauth/token").get()).isEqualTo(1); // password grant only
    }

    @Test
    void mastodonToken_registersWhenGrantRefused_userTokenReturnedDirectly() {
        var hits = new java.util.HashMap<String, java.util.concurrent.atomic.AtomicInteger>();
        ServiceTokenBroker broker = routedBroker(java.util.Map.of(
                "/api/v1/apps", java.util.List.of(json(HttpStatus.OK, APP_CREDS)),
                "/oauth/token", java.util.List.of(
                        json(HttpStatus.BAD_REQUEST, "{\"error\":\"invalid_grant\"}"),   // password grant
                        json(HttpStatus.OK, "{\"access_token\":\"app-tok\"}")),          // client_credentials
                "/api/v1/accounts", java.util.List.of(json(HttpStatus.OK,
                        "{\"access_token\":\"mst_new\",\"token_type\":\"Bearer\"}"))), hits);

        StepVerifier.create(broker.mastodonToken("bob", "bob"))
                .assertNext(out -> assertThat(out.get("access_token")).isEqualTo("mst_new"))
                .verifyComplete();
        assertThat(hits.get("/oauth/token").get()).isEqualTo(2);
        assertThat(hits.get("/api/v1/accounts").get()).isEqualTo(1);
    }

    @Test
    void mastodonToken_bothLegsRefused_failsClosed() {
        var hits = new java.util.HashMap<String, java.util.concurrent.atomic.AtomicInteger>();
        ServiceTokenBroker broker = routedBroker(java.util.Map.of(
                "/api/v1/apps", java.util.List.of(json(HttpStatus.OK, APP_CREDS)),
                "/oauth/token", java.util.List.of(
                        json(HttpStatus.BAD_REQUEST, "{\"error\":\"invalid_grant\"}"),
                        json(HttpStatus.OK, "{\"access_token\":\"app-tok\"}")),
                "/api/v1/accounts", java.util.List.of(json(HttpStatus.UNPROCESSABLE_CONTENT,
                        "{\"error\":\"Validation failed: Username has already been taken\"}"))), hits);

        StepVerifier.create(broker.mastodonToken("bob", "bob"))
                .expectErrorSatisfies(e -> assertThat(e).hasMessageContaining("no access_token"))
                .verify();
    }

    @Test
    void mastodonToken_localpartFoldedAndCapped() {
        assertThat(ServiceTokenBroker.mastodonLocalpart("Bea59B50-15a1.x"))
                .isEqualTo("bea59b50_15a1_x");
        assertThat(ServiceTokenBroker.mastodonLocalpart("bea59b50-15a1-4efc-82de-87d3fe9b2322"))
                .isEqualTo("bea59b50_15a1_4efc_82de_87d3fe")
                .hasSize(30);
        assertThat(ServiceTokenBroker.mastodonLocalpart("---")).isEqualTo("user");
    }

    @Test
    void mastodonToken_failsClosed_whenEmailDomainUnset() {
        WebClient hs = WebClient.builder()
                .exchangeFunction(jsonStub("{\"access_token\":\"should-not-be-reached\"}"))
                .build();
        SuspensionService suspensions = mock(SuspensionService.class);
        when(suspensions.isLocalpartSuspended(any(), any())).thenReturn(Mono.just(false));
        HsTokenRegistry hsTokens = mock(HsTokenRegistry.class);
        when(hsTokens.recordBrokered(any(), any(), any())).thenReturn(Mono.empty());
        ServiceTokenBroker broker =
                new ServiceTokenBroker(hs, hs, "svc-pw", "", suspensions, hsTokens);

        StepVerifier.create(broker.mastodonToken("bob", "bob"))
                .expectErrorSatisfies(e ->
                        assertThat(e).hasMessageContaining("email domain not configured"))
                .verify();
    }
}
