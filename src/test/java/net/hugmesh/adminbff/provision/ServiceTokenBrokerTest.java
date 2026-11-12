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

    // ── Display name reconcile (Casdoor username) ──────────────────────────────────────

    /** One recorded homeserver request: method, path and (for writes) the body sent. */
    private record Seen(String method, String path, String auth) { }

    /**
     * A stub homeserver keyed on "METHOD path": answers from {@code routes} (404 when
     * unrouted) and records every request in {@code seen}, so a test can assert which
     * profile writes happened. Response bodies are rebuilt per call.
     */
    private static ExchangeFunction recordingStub(java.util.Map<String, String> routes,
                                                  java.util.List<Seen> seen,
                                                  java.util.List<String> writeBodies) {
        return request -> {
            String key = request.method().name() + " " + request.url().getRawPath();
            seen.add(new Seen(request.method().name(), request.url().getRawPath(),
                    request.headers().getFirst("Authorization")));
            Mono<Void> capture = Mono.empty();
            if (request.method().name().equals("PUT") || request.method().name().equals("PATCH")) {
                org.springframework.mock.http.client.reactive.MockClientHttpRequest mock =
                        new org.springframework.mock.http.client.reactive.MockClientHttpRequest(
                                request.method(), request.url());
                capture = request.body().insert(mock, new org.springframework.web.reactive.function
                                .BodyInserter.Context() {
                            @Override public java.util.List<org.springframework.http.codec.HttpMessageWriter<?>> messageWriters() {
                                return org.springframework.web.reactive.function.client.ExchangeStrategies
                                        .withDefaults().messageWriters();
                            }
                            @Override public java.util.Optional<org.springframework.http.server.reactive.ServerHttpRequest> serverRequest() {
                                return java.util.Optional.empty();
                            }
                            @Override public java.util.Map<String, Object> hints() {
                                return java.util.Map.of();
                            }
                        })
                        .then(Mono.defer(() -> org.springframework.core.io.buffer.DataBufferUtils
                                .join(mock.getBody())
                                .map(buf -> buf.toString(java.nio.charset.StandardCharsets.UTF_8))
                                .doOnNext(writeBodies::add)
                                .then()));
            }
            String body = routes.get(key);
            return capture.then(Mono.just(body == null
                    ? json(HttpStatus.NOT_FOUND, "{\"errcode\":\"M_NOT_FOUND\"}")
                    : json(HttpStatus.OK, body)));
        };
    }

    private static ServiceTokenBroker brokerOn(ExchangeFunction ex) {
        WebClient hs = WebClient.builder().exchangeFunction(ex).build();
        SuspensionService suspensions = mock(SuspensionService.class);
        when(suspensions.isLocalpartSuspended(any(), any())).thenReturn(Mono.just(false));
        HsTokenRegistry hsTokens = mock(HsTokenRegistry.class);
        when(hsTokens.recordBrokered(any(), any(), any())).thenReturn(Mono.empty());
        return new ServiceTokenBroker(hs, hs, "svc-pw", suspensions, hsTokens);
    }

    private static final String UUID_LP = "c18f905c-62a1-4c20-a7c5-c707fb6eae85";
    private static final String UUID_MXID = "@" + UUID_LP + ":localhost";
    private static final String PROFILE_PATH = "/_matrix/client/v3/profile/" + UUID_MXID + "/displayname";

    /** The live defect: tuwunel's default "<uuid> 💕" display name is replaced by the
     *  Casdoor username, with the user's own freshly minted token. */
    @Test
    void matrixToken_defaultDisplayName_isSetToCasdoorUsername() {
        var seen = new java.util.ArrayList<Seen>();
        var writes = new java.util.ArrayList<String>();
        ServiceTokenBroker broker = brokerOn(recordingStub(java.util.Map.of(
                "POST /_matrix/client/v3/register",
                "{\"access_token\":\"mx_tok\",\"user_id\":\"" + UUID_MXID + "\"}",
                "GET " + PROFILE_PATH, "{\"displayname\":\"" + UUID_LP + " \uD83D\uDC95\"}",
                "PUT " + PROFILE_PATH, "{}"), seen, writes));

        StepVerifier.create(broker.matrixToken(UUID_LP, "e2e-matrix"))
                .assertNext(out -> assertThat(out.get("access_token")).isEqualTo("mx_tok"))
                .verifyComplete();

        assertThat(seen).anySatisfy(r -> {
            assertThat(r.method()).isEqualTo("PUT");
            assertThat(r.path()).isEqualTo(PROFILE_PATH);
            assertThat(r.auth()).isEqualTo("Bearer mx_tok");
        });
        assertThat(writes).containsExactly("{\"displayname\":\"e2e-matrix\"}");
    }

    /** A name the user chose (matrix-ui lets them set one) is never overwritten. */
    @Test
    void matrixToken_userChosenDisplayName_isLeftAlone() {
        var seen = new java.util.ArrayList<Seen>();
        var writes = new java.util.ArrayList<String>();
        ServiceTokenBroker broker = brokerOn(recordingStub(java.util.Map.of(
                "POST /_matrix/client/v3/register",
                "{\"access_token\":\"mx_tok\",\"user_id\":\"" + UUID_MXID + "\"}",
                "GET " + PROFILE_PATH, "{\"displayname\":\"Trinity\"}",
                "PUT " + PROFILE_PATH, "{}"), seen, writes));

        StepVerifier.create(broker.matrixToken(UUID_LP, "e2e-matrix")).expectNextCount(1).verifyComplete();
        assertThat(seen).noneSatisfy(r -> assertThat(r.method()).isEqualTo("PUT"));
        assertThat(writes).isEmpty();
    }

    /** No display name known (a google/discord account, or the 1-arg overload): no profile
     *  traffic at all, the mint is exactly what it was. */
    @Test
    void matrixToken_noDisplayName_noProfileTraffic() {
        var seen = new java.util.ArrayList<Seen>();
        ServiceTokenBroker broker = brokerOn(recordingStub(java.util.Map.of(
                "POST /_matrix/client/v3/register",
                "{\"access_token\":\"mx_tok\",\"user_id\":\"" + UUID_MXID + "\"}"),
                seen, new java.util.ArrayList<>()));
        StepVerifier.create(broker.matrixToken(UUID_LP, "")).expectNextCount(1).verifyComplete();
        StepVerifier.create(broker.matrixToken(UUID_LP)).expectNextCount(1).verifyComplete();
        assertThat(seen).allSatisfy(r -> assertThat(r.path()).isEqualTo("/_matrix/client/v3/register"));
    }

    /** A failing profile write never fails the mint (best effort). */
    @Test
    void matrixToken_profileWriteFails_mintStillSucceeds() {
        ServiceTokenBroker broker = brokerOn(request -> {
            String path = request.url().getRawPath();
            if (path.equals("/_matrix/client/v3/register")) {
                return Mono.just(json(HttpStatus.OK,
                        "{\"access_token\":\"mx_tok\",\"user_id\":\"" + UUID_MXID + "\"}"));
            }
            if (request.method().name().equals("GET")) {
                return Mono.just(json(HttpStatus.NOT_FOUND, "{}"));
            }
            return Mono.error(new IllegalStateException("homeserver down"));
        });
        StepVerifier.create(broker.matrixToken(UUID_LP, "e2e-matrix"))
                .assertNext(out -> assertThat(out.get("access_token")).isEqualTo("mx_tok"))
                .verifyComplete();
    }

    private static final String MST_LP = "c18f905c_62a1_4c20_a7c5_c707fb";

    /** Mastodon/Akkoma: an empty display_name (the live state of every UUID account) is set
     *  to the Casdoor username via update_credentials, with the user token. */
    @Test
    void mastodonToken_emptyDisplayName_isSetToCasdoorUsername() {
        var seen = new java.util.ArrayList<Seen>();
        var writes = new java.util.ArrayList<String>();
        ServiceTokenBroker broker = brokerOn(recordingStub(java.util.Map.of(
                "POST /api/v1/apps", APP_CREDS,
                "POST /oauth/token", "{\"access_token\":\"mst_tok\",\"token_type\":\"Bearer\"}",
                "GET /api/v1/accounts/verify_credentials",
                "{\"username\":\"" + MST_LP + "\",\"display_name\":\"\"}",
                "PATCH /api/v1/accounts/update_credentials", "{}"), seen, writes));

        StepVerifier.create(broker.mastodonToken(UUID_LP, MST_LP, "e2e-matrix"))
                .assertNext(out -> assertThat(out.get("access_token")).isEqualTo("mst_tok"))
                .verifyComplete();
        assertThat(seen).anySatisfy(r -> {
            assertThat(r.method()).isEqualTo("PATCH");
            assertThat(r.path()).isEqualTo("/api/v1/accounts/update_credentials");
            assertThat(r.auth()).isEqualTo("Bearer mst_tok");
        });
        assertThat(writes).containsExactly("{\"display_name\":\"e2e-matrix\"}");
    }

    @Test
    void mastodonToken_userChosenDisplayName_isLeftAlone() {
        var seen = new java.util.ArrayList<Seen>();
        var writes = new java.util.ArrayList<String>();
        ServiceTokenBroker broker = brokerOn(recordingStub(java.util.Map.of(
                "POST /api/v1/apps", APP_CREDS,
                "POST /oauth/token", "{\"access_token\":\"mst_tok\",\"token_type\":\"Bearer\"}",
                "GET /api/v1/accounts/verify_credentials",
                "{\"username\":\"" + MST_LP + "\",\"display_name\":\"Morpheus\"}"), seen, writes));
        StepVerifier.create(broker.mastodonToken(UUID_LP, MST_LP, "e2e-matrix"))
                .expectNextCount(1).verifyComplete();
        assertThat(writes).isEmpty();
    }

    @Test
    void isDefaultDisplayName_rules() {
        assertThat(ServiceTokenBroker.isDefaultDisplayName(null, "bob")).isTrue();
        assertThat(ServiceTokenBroker.isDefaultDisplayName("", "bob")).isTrue();
        assertThat(ServiceTokenBroker.isDefaultDisplayName("bob", "bob")).isTrue();
        assertThat(ServiceTokenBroker.isDefaultDisplayName("bob \uD83D\uDC95", "bob")).isTrue();
        assertThat(ServiceTokenBroker.isDefaultDisplayName("bob \u2764\uFE0F", "bob")).isTrue();
        assertThat(ServiceTokenBroker.isDefaultDisplayName("bob smith", "bob")).isFalse();
        assertThat(ServiceTokenBroker.isDefaultDisplayName("bobby", "bob")).isFalse();
        assertThat(ServiceTokenBroker.isDefaultDisplayName("Alice", "bob")).isFalse();
    }

    @Test
    void cleanDisplayName_stripsControlsAndCaps() {
        assertThat(ServiceTokenBroker.cleanDisplayName("a\u0000b\nc", 30)).isEqualTo("abc");
        assertThat(ServiceTokenBroker.cleanDisplayName("x".repeat(40), 30)).hasSize(30);
        assertThat(ServiceTokenBroker.cleanDisplayName("  ", 30)).isNull();
        assertThat(ServiceTokenBroker.cleanDisplayName(null, 30)).isNull();
    }
}
