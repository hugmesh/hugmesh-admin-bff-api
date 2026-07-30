package systems.hugmesh.adminbff.notification;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves the part-A AUTH MECHANISM is reused VERBATIM by the outbound user-bff call:
 * a Casdoor ROLE_SERVICE token minted via the OAuth2 {@code client_credentials} grant,
 * presented as {@code Authorization: Bearer <token>}.
 *
 * <p>Two legs, no network:
 * <ul>
 *   <li><b>SEND</b> — the {@link UserBffNotificationClient} forwards the supplied service
 *       bearer on the POST to {@code /bff/user/internal/notifications} (the contract path)
 *       — captured via a stub {@link ExchangeFunction}.</li>
 *   <li><b>MINT</b> — the {@link UserBffNotificationConfig} token supplier POSTs a
 *       {@code grant_type=client_credentials} form to Casdoor's
 *       {@code /api/login/oauth/access_token} and caches the returned token — captured
 *       via a stub {@link ExchangeFunction} over the Casdoor WebClient.</li>
 * </ul>
 */
class UserBffNotificationClientAuthTest {

    // ── SEND: the call carries Authorization: Bearer <service token> ────────
    @Test
    void deliverInApp_sendsBearerServiceToken_onContractPath() {
        AtomicReference<ClientRequest> captured = new AtomicReference<>();
        ExchangeFunction capture = req -> {
            captured.set(req);
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .body("{\"delivered\":true}")
                    .build());
        };
        WebClient http = WebClient.builder().exchangeFunction(capture).build();
        Supplier<Mono<String>> token = () -> Mono.just("svc-jwt-ROLE_SERVICE");
        UserBffNotificationClient client = new UserBffNotificationClient(http, true, token);

        var outcome = client.deliverInApp(new UserBffNotification(
                "brandx", "subject-alice", "account-restriction",
                "Your account access changed", "body",
                "access_suspension", "src-1")).block();

        assertThat(outcome).isEqualTo(UserBffNotificationClient.Outcome.DELIVERED);
        ClientRequest sent = captured.get();
        assertThat(sent).isNotNull();
        assertThat(sent.method()).isEqualTo(HttpMethod.POST);
        // The contract path.
        assertThat(sent.url().getPath()).isEqualTo("/bff/user/internal/notifications");
        // Reused VERBATIM: Authorization: Bearer <service token>.
        assertThat(sent.headers().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer svc-jwt-ROLE_SERVICE");
    }

    // ── GATE OFF: no call, no token use, terminal SUPPRESSED ────────────────
    @Test
    void gateOff_makesNoCall_andNeverTouchesTheTokenSupplier() {
        AtomicReference<Boolean> called = new AtomicReference<>(false);
        ExchangeFunction explode = req -> {
            called.set(true);
            return Mono.error(new AssertionError("no call expected when gate off"));
        };
        WebClient http = WebClient.builder().exchangeFunction(explode).build();
        Supplier<Mono<String>> token = () -> Mono.error(new AssertionError("token not expected"));
        UserBffNotificationClient client = new UserBffNotificationClient(http, false, token);

        var outcome = client.deliverInApp(new UserBffNotification(
                "brandx", "s", "account-restriction", "t", "b", "access_suspension", "src-2")).block();

        assertThat(outcome).isEqualTo(UserBffNotificationClient.Outcome.SUPPRESSED);
        assertThat(called.get()).isFalse();
    }

    // ── TRANSPORT ERROR maps to FAILED (record nothing, retry) ──────────────
    @Test
    void transportError_mapsToFailed_neverThrows() {
        ExchangeFunction boom = req -> Mono.error(new RuntimeException("connection refused"));
        WebClient http = WebClient.builder().exchangeFunction(boom).build();
        UserBffNotificationClient client = new UserBffNotificationClient(
                http, true, () -> Mono.just("svc-jwt"));

        var outcome = client.deliverInApp(new UserBffNotification(
                "brandx", "s", "account-restriction", "t", "b", "access_suspension", "src-3")).block();

        assertThat(outcome).isEqualTo(UserBffNotificationClient.Outcome.FAILED);
    }

    // ── delivered:false maps to terminal SUPPRESSED ─────────────────────────
    @Test
    void deliveredFalse_mapsToSuppressed() {
        ExchangeFunction ok = req -> Mono.just(ClientResponse.create(HttpStatus.OK)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body("{\"delivered\":false}")
                .build());
        WebClient http = WebClient.builder().exchangeFunction(ok).build();
        UserBffNotificationClient client = new UserBffNotificationClient(
                http, true, () -> Mono.just("svc-jwt"));

        var outcome = client.deliverInApp(new UserBffNotification(
                "brandx", "s", "account-restriction", "t", "b", "access_suspension", "src-4")).block();

        assertThat(outcome).isEqualTo(UserBffNotificationClient.Outcome.SUPPRESSED);
    }

    // ── MINT: the token supplier uses the client_credentials grant ──────────
    @Test
    void tokenSupplier_mintsViaClientCredentialsGrant_againstCasdoor() {
        AtomicReference<ClientRequest> mintReq = new AtomicReference<>();
        AtomicReference<String> body = new AtomicReference<>();
        ExchangeFunction casdoorStub = req -> {
            mintReq.set(req);
            // Capture the form body the grant sent.
            body.set(extractBody(req));
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .body("{\"access_token\":\"minted-svc-token\",\"expires_in\":3600}")
                    .build());
        };
        WebClient casdoor = WebClient.builder().exchangeFunction(casdoorStub).build();
        Supplier<Mono<String>> supplier =
                UserBffNotificationConfig.serviceTokenSupplier(casdoor, "app-admin-bff", "secret");

        String first = supplier.get().block();
        assertThat(first).isEqualTo("minted-svc-token");
        ClientRequest req = mintReq.get();
        assertThat(req.method()).isEqualTo(HttpMethod.POST);
        assertThat(req.url().getPath()).isEqualTo("/api/login/oauth/access_token");
        assertThat(body.get()).contains("grant_type=client_credentials");
        assertThat(body.get()).contains("client_id=app-admin-bff");

        // Cached: a second get within TTL does NOT re-mint (still the same captured req).
        ClientRequest before = mintReq.get();
        String second = supplier.get().block();
        assertThat(second).isEqualTo("minted-svc-token");
        assertThat(mintReq.get()).isSameAs(before);
    }

    /** Render the outgoing form body of a captured client_credentials request, using
     *  Spring's spring-test MockClientHttpRequest which buffers the inserted body. */
    private static String extractBody(ClientRequest req) {
        var mock = new org.springframework.mock.http.client.reactive.MockClientHttpRequest(
                HttpMethod.POST, "/api/login/oauth/access_token");
        req.writeTo(mock, org.springframework.web.reactive.function.client.ExchangeStrategies.withDefaults())
                .block();
        return mock.getBodyAsString().block();
    }
}
