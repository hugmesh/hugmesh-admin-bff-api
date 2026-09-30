package net.hugmesh.adminbff.provision;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.suspension.AccessSuspension;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Brokers REAL Matrix (tuwunel) and Mastodon access tokens server-side (reactive),
 * so the admin-ui / login-ui never hold homeserver admin credentials — the BFF
 * mints them against the real services and hands back just the user's access
 * token. The reactive port of the mock-bff {@code matrixToken} / {@code
 * mastodonToken} brokering, with the same register-then-login fallback against
 * tuwunel.
 *
 * <p>Only callable once the account's registration is complete (the controller
 * enforces the two-stage gate before delegating here).
 */
@Service
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class ServiceTokenBroker {

    private static final Logger log = LoggerFactory.getLogger(ServiceTokenBroker.class);

    /**
     * Jackson-2 mapper used to parse homeserver JSON responses OFF the WebFlux
     * codec path (see {@link #postJson}). Boot 4's reactive JSON codec is Jackson 3
     * (tools.jackson), which cannot decode into this Jackson-2 {@link JsonNode}
     * type — so the response is read as a String (always codec-safe) and parsed
     * here. Thread-safe for {@code readTree}.
     */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** OAuth scopes for the broker's app + minted user tokens (Mastodon/Akkoma). */
    private static final String MASTODON_SCOPES = "read write follow";

    private final WebClient tuwunel;
    private final WebClient mastodon;
    private final String svcPassword;
    private final String mastodonEmailDomain;
    private final SuspensionService suspensions;
    private final HsTokenRegistry hsTokens;

    /** Lazily-registered doorkeeper app creds ({@code client_id}/{@code client_secret})
     *  — see {@link #ensureMastodonApp}. In-process cache only. */
    private final java.util.concurrent.atomic.AtomicReference<JsonNode> mastodonApp =
            new java.util.concurrent.atomic.AtomicReference<>();

    /**
     * Base URLs default to the DIRECT homeserver services (works today). The
     * account-states design repoints them at the per-pod mTLS proxy sidecars
     * (akkoma-proxy:4443 / tuwunel-proxy:4443) so brokered traffic is gated by the
     * gateway revocation filter — DOCUMENTED here and config-only: the deployment
     * overrides {@code broker.synapse-url}/{@code broker.mastodon-url} to the
     * {@code *-proxy:4443} services (presenting client certs) once those sidecars
     * exist. Until the proxy is present the defaults below keep the broker working.
     *
     * <p>{@code broker.synapse-url} is a FROZEN Spring property name — the k8s
     * deployment manifest and every local compose profile set the env var
     * {@code SYNAPSE_URL} to bind it, even though the homeserver behind it is
     * tuwunel (a Synapse-COMPATIBLE server, hence the name). Do not rename the
     * property key without a coordinated change across every repo that sets it.
     */
    @Autowired
    public ServiceTokenBroker(
            @Value("${broker.synapse-url:http://tuwunel.hugmesh-backend.svc.cluster.local:8008}") String tuwunelUrl,
            @Value("${broker.mastodon-url:http://mastodon-web.hugmesh-backend.svc.cluster.local:3000}") String mastodonUrl,
            // No default: the insecure literal lives nowhere. broker.svc-password resolves
            // from the MANDATORY ${SVC_PASSWORD} in application.yml, so a missing secret
            // fails context startup rather than falling back to a known credential.
            @Value("${broker.svc-password}") String svcPassword,
            @Value("${broker.mastodon-email-domain:}") String mastodonEmailDomain,
            SuspensionService suspensions,
            HsTokenRegistry hsTokens) {
        this.tuwunel = WebClient.builder().baseUrl(tuwunelUrl).build();
        // Plain-HTTP homeserver base (compose talks to mastodon-web:3000 directly, no
        // TLS sidecar): assert the edge protocol or mainline Mastodon's force_ssl 308s
        // every API call (its /health is exempt, so the service LOOKS fine while every
        // real call bounces). An https sidecar leg never gets the header — the sidecar
        // owns proto metadata.
        WebClient.Builder mastodonBuilder = WebClient.builder().baseUrl(mastodonUrl);
        if (mastodonUrl != null && mastodonUrl.startsWith("http://")) {
            mastodonBuilder.defaultHeader("X-Forwarded-Proto", "https");
        }
        this.mastodon = mastodonBuilder.build();
        this.svcPassword = svcPassword;
        this.mastodonEmailDomain = mastodonEmailDomain;
        this.suspensions = suspensions;
        this.hsTokens = hsTokens;
    }

    /**
     * Test seam — inject pre-built {@link WebClient}s (e.g. backed by a stub
     * exchange) so the JSON decode path can be exercised without a live
     * homeserver. Production uses the {@code @Autowired} constructor above.
     */
    ServiceTokenBroker(WebClient tuwunel, WebClient mastodon, String svcPassword,
                       SuspensionService suspensions, HsTokenRegistry hsTokens) {
        this(tuwunel, mastodon, svcPassword, "e2e.local", suspensions, hsTokens);
    }

    /** Test seam with an explicit mastodon email domain. */
    ServiceTokenBroker(WebClient tuwunel, WebClient mastodon, String svcPassword,
                       String mastodonEmailDomain,
                       SuspensionService suspensions, HsTokenRegistry hsTokens) {
        this.tuwunel = tuwunel;
        this.mastodon = mastodon;
        this.svcPassword = svcPassword;
        this.mastodonEmailDomain = mastodonEmailDomain;
        this.suspensions = suspensions;
        this.hsTokens = hsTokens;
    }

    /** Sanitise a handle into a Matrix localpart (mirrors the mock's matrixUser). */
    public static String matrixUser(String handle) {
        String base = (handle == null ? "user" : handle).split("@")[0].toLowerCase();
        String cleaned = base.replaceAll("[^a-z0-9._=/-]", "");
        return cleaned.isEmpty() ? "user" : cleaned;
    }

    /**
     * Mint (or recover) a tuwunel access token: register, else password-login.
     * Refuses a localpart under an active ROLE_MATRIX suspension (the table is the
     * source of truth, so a suspended user can never re-broker a token even if the
     * homeserver account leg is still stubbed). On success the brokered token is
     * recorded in the hs_tokens registry (kind=brokered).
     */
    public Mono<Map<String, Object>> matrixToken(String username) {
        // Guard suspension, then register or login to tuwunel and record the brokered token.
        return guardSuspended(username, AccessSuspension.ROLE_MATRIX)
                .then(Mono.defer(() -> tuwunelRegisterOrLogin(username)
                        .flatMap(out -> recordBrokered(out, username, "matrix"))));
    }

    /**
     * Mastodon/Akkoma localparts allow ONLY {@code [a-z0-9_]} (Mastodon rejects the
     * {@code .-=/} the Matrix charset permits) and are capped at 30 CHARACTERS —
     * live-verified against mainline v4.3. Disallowed characters FOLD to {@code '_'}
     * (position-preserving); over-long names TRUNCATE to 30. Mirrors user-bff-api's
     * {@code ServiceTokenBroker.mastodonLocalpart}.
     */
    public static String mastodonLocalpart(String handle) {
        String base = (handle == null ? "user" : handle).split("@")[0].toLowerCase();
        String cleaned = base.replaceAll("[^a-z0-9_]", "_");
        if (cleaned.length() > 30) {
            cleaned = cleaned.substring(0, 30);
        }
        return cleaned.replaceAll("_", "").isEmpty() ? "user" : cleaned;
    }

    /**
     * Mint (or recover) a Mastodon/Akkoma access token — the REAL OAuth contract
     * (live-verified against mainline Mastodon v4.3; Pleroma/Akkoma implements the
     * same endpoints). The previous bare {@code {grant_type,username,password}} body
     * (a mock-bff port) never worked against any real doorkeeper ({@code 401
     * invalid_client} without {@code client_id}/{@code client_secret}):
     *
     * <ol>
     *   <li><b>ensure an OAuth app</b> — {@code POST /api/v1/apps} (unauthenticated),
     *       cached in-process;</li>
     *   <li><b>recover</b> — password grant WITH the app creds, {@code username} = the
     *       account EMAIL ({@code <localpart>@broker.mastodon-email-domain}; Mastodon
     *       authenticates by email, Pleroma accepts either);</li>
     *   <li><b>register</b> — on an empty/invalid grant, {@code client_credentials} →
     *       app token → {@code POST /api/v1/accounts}, which returns a USER token
     *       directly (instance registrations must be open; mainline holds fresh
     *       accounts at 403 until email-confirm — Akkoma requires no activation). A
     *       localpart owned by an account this broker did not register fails BOTH
     *       legs → fail-closed, never a takeover.</li>
     * </ol>
     *
     * <p>Refuses a localpart under an active ROLE_MASTODON suspension; fail-closed
     * 503 when {@code broker.mastodon-email-domain} is unset (the email is
     * load-bearing for both legs); records the brokered token (kind=brokered).
     *
     * @param username the MATRIX-style localpart (the suspension row key) — guarded, not
     *                 sent to the homeserver
     * @param persistedMastodonLocalpart the PERSISTED, collision-checked Mastodon localpart
     *                 (changeset 291) the homeserver account is keyed on — never re-derived
     *                 here (see {@link net.hugmesh.adminbff.account.AccountLocalpartService})
     */
    public Mono<Map<String, Object>> mastodonToken(String username, String persistedMastodonLocalpart) {
        // Guard on the MATRIX-style `username` (= matrixUser(handle), the exact string
        // SuspensionService stores EVERY role's rows under, incl. ROLE_MASTODON — same key
        // matrixToken() guards on), NOT the mastodon-folded localpart. mastodonLocalpart
        // folds `.`/`-`/`=`/`/`->`_` and 30-caps, so a dotted/hyphenated/>30-char handle's
        // folded form never equals its stored suspension row's localpart -> the guard would
        // silently miss and a MASTODON-suspended user could re-mint.
        return guardSuspended(username, AccessSuspension.ROLE_MASTODON)
                .then(Mono.defer(() -> mintMastodon(persistedMastodonLocalpart)));
    }

    private Mono<Map<String, Object>> mintMastodon(String persistedMastodonLocalpart) {
        if (mastodonEmailDomain == null || mastodonEmailDomain.isBlank()) {
            log.warn("[broker] mastodon mint refused: broker.mastodon-email-domain is unset (fail-closed)");
            return Mono.error(ApiException.badGateway(
                    "mastodon token brokering unavailable: email domain not configured"));
        }
        // Use the PERSISTED, collision-checked Mastodon localpart (changeset 291;
        // AuthController#provision reads AccountLocalpartService.mastodonLocalpartOf) — NEVER
        // a re-fold of `username` here, which would skip the account-takeover-by-collision
        // uniqueness the persisted value carries (two 290-unique accounts can share the
        // coarser Mastodon fold). The mastodonLocalpart() re-application is idempotent (the
        // stored value is already a fold fixed point), a belt-and-braces guard only.
        String user = mastodonLocalpart(persistedMastodonLocalpart);
        String email = user + "@" + mastodonEmailDomain;
        return ensureMastodonApp()
                .flatMap(app -> mastodonPasswordGrant(app, email)
                        .switchIfEmpty(Mono.defer(() -> mastodonRegister(app, user, email))))
                .flatMap(node -> node.hasNonNull("access_token")
                        ? Mono.just(tokenOut(node))
                        : Mono.error(new RuntimeException("mastodon mint: no access_token")))
                .flatMap(out -> recordBrokered(out, user, "mastodon"));
    }

    /**
     * The OAuth app this broker mints through, created lazily via the unauthenticated
     * {@code POST /api/v1/apps} and cached in-process (a lost race just creates one
     * extra doorkeeper app row — harmless). Never persisted; a restart re-registers.
     */
    private Mono<JsonNode> ensureMastodonApp() {
        JsonNode cached = mastodonApp.get();
        if (cached != null) {
            return Mono.just(cached);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("client_name", "hugmesh-admin-bff-broker");
        body.put("redirect_uris", "urn:ietf:wg:oauth:2.0:oob");
        body.put("scopes", MASTODON_SCOPES);
        return postJsonTolerant(mastodon, "/api/v1/apps", body, null)
                .flatMap(node -> {
                    if (!node.hasNonNull("client_id") || !node.hasNonNull("client_secret")) {
                        return Mono.error(new RuntimeException(
                                "mastodon mint: app registration returned no client credentials"));
                    }
                    mastodonApp.compareAndSet(null, node);
                    return Mono.just(mastodonApp.get());
                });
    }

    /** Password-grant recover leg: yields the token node, or EMPTY when the grant is
     *  refused (unknown account / wrong password — the cue to try registration). */
    private Mono<JsonNode> mastodonPasswordGrant(JsonNode app, String email) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("grant_type", "password");
        body.put("username", email);
        body.put("password", svcPassword);
        body.put("client_id", app.path("client_id").asText());
        body.put("client_secret", app.path("client_secret").asText());
        body.put("scope", MASTODON_SCOPES);
        return postJsonTolerant(mastodon, "/oauth/token", body, null)
                .filter(node -> node.hasNonNull("access_token"));
    }

    /** Register leg: client_credentials app token → {@code POST /api/v1/accounts},
     *  which returns a USER token directly. */
    private Mono<JsonNode> mastodonRegister(JsonNode app, String user, String email) {
        Map<String, Object> tokenBody = new LinkedHashMap<>();
        tokenBody.put("grant_type", "client_credentials");
        tokenBody.put("client_id", app.path("client_id").asText());
        tokenBody.put("client_secret", app.path("client_secret").asText());
        tokenBody.put("scope", MASTODON_SCOPES);
        return postJsonTolerant(mastodon, "/oauth/token", tokenBody, null)
                .flatMap(tok -> registerWithAppToken(tok, user, email));
    }

    private Mono<JsonNode> registerWithAppToken(JsonNode tok, String user, String email) {
        if (!tok.hasNonNull("access_token")) {
            return Mono.error(new RuntimeException(
                    "mastodon mint: client_credentials grant returned no app token"));
        }
        Map<String, Object> reg = new LinkedHashMap<>();
        reg.put("username", user);
        reg.put("email", email);
        reg.put("password", svcPassword);
        reg.put("agreement", true);
        reg.put("locale", "en");
        return postJsonTolerant(mastodon, "/api/v1/accounts", reg,
                "Bearer " + tok.path("access_token").asText());
    }

    /**
     * Like {@link #postJson} but PARSES 4xx protocol bodies instead of throwing (the
     * doorkeeper endpoints speak through them: {@code invalid_grant} on the recover
     * leg, validation errors on register) — only 5xx (a homeserver-side failure with
     * no protocol meaning) propagates as an error. Mirrors {@link #tuwunelRegister}'s
     * UIAA tolerance. Optional {@code authorization} header for the app-token leg.
     */
    private Mono<JsonNode> postJsonTolerant(WebClient client, String path, Object body,
                                            String authorization) {
        WebClient.RequestBodySpec spec = client.post().uri(path)
                .contentType(MediaType.APPLICATION_JSON);
        if (authorization != null) {
            spec = spec.header("Authorization", authorization);
        }
        return spec.bodyValue(body)
                .exchangeToMono(resp -> resp.statusCode().is5xxServerError()
                        ? resp.createException().flatMap(e -> Mono.<String>error(e))
                        : resp.bodyToMono(String.class))
                .flatMap(ServiceTokenBroker::parseJson)
                .switchIfEmpty(Mono.fromSupplier(JsonNodeFactory.instance::objectNode));
    }

    /** Register with tuwunel (two-stage if dummy auth required), falling back to password login. */
    private Mono<Map<String, Object>> tuwunelRegisterOrLogin(String username) {
        return tuwunelRegister(username, null).flatMap(reg -> resolveRegistrationResponse(reg, username));
    }

    /** Interpret the initial registration response: return token, attempt stage-2, or login. */
    private Mono<Map<String, Object>> resolveRegistrationResponse(JsonNode reg, String username) {
        if (reg.hasNonNull("access_token")) {
            return Mono.just(tokenOut(reg));
        }
        String regSession = reg.path("session").asText(null);
        Mono<JsonNode> stage2 = (regSession != null)
                ? tuwunelRegister(username, Map.of("type", "m.login.dummy", "session", regSession))
                : Mono.empty();
        return stage2.flatMap(reg2 -> reg2.hasNonNull("access_token")
                        ? Mono.just(tokenOut(reg2)) : Mono.<Map<String, Object>>empty())
                // Already registered → password login.
                .switchIfEmpty(tuwunelLogin(username).flatMap(login -> {
                    if (login.hasNonNull("access_token")) return Mono.just(tokenOut(login));
                    return Mono.error(new RuntimeException("tuwunel: " + login));
                }));
    }

    /**
     * Refuse to register/login a localpart that is under an active suspension on the
     * platform role. The access_suspension table is the source of truth, so this
     * holds even while the homeserver account-state leg is still a stub-seam.
     */
    private Mono<Void> guardSuspended(String localpart, String role) {
        return suspensions.isLocalpartSuspended(localpart, role)
                .flatMap(suspended -> {
                    if (Boolean.TRUE.equals(suspended)) {
                        log.info("[broker] refused token mint for suspended localpart '{}' ({})", localpart, role);
                        return Mono.error(ApiException.forbidden(
                                "account '" + localpart + "' is suspended"));
                    }
                    return Mono.empty();
                });
    }

    /** Record the freshly-minted brokered token in the hs_tokens registry, then pass it through. */
    private Mono<Map<String, Object>> recordBrokered(Map<String, Object> out, String localpart, String platform) {
        Object token = out.get("access_token");
        if (token == null) return Mono.just(out);
        return hsTokens.recordBrokered(token.toString(), localpart, platform).thenReturn(out);
    }

    // ── tuwunel helpers (Matrix client-server API, Synapse-compatible) ──────
    /**
     * Matrix client registration POST that TOLERATES the spec's non-2xx control
     * responses so the User-Interactive-Auth (UIAA) handshake can complete. Per the
     * Matrix client-server spec, {@code POST /register}:
     * <ul>
     *   <li>returns <b>HTTP 401</b> carrying the UIAA challenge body
     *       ({@code session}+{@code flows}) — NOT an error, but the prompt to repeat
     *       the call with {@code auth.session}; and</li>
     *   <li>returns <b>HTTP 400</b> {@code M_USER_IN_USE} when the localpart already
     *       exists — the cue to fall back to password login.</li>
     * </ul>
     * A plain {@code .retrieve()} raises {@code WebClientResponseException} on both,
     * short-circuiting {@link #resolveRegistrationResponse} (and the login fallback)
     * before it can read the body — so a real homeserver (e.g. tuwunel or Synapse)
     * could NEVER be provisioned. Here both 400 and 401 are read as JSON and passed
     * through; every other 4xx/5xx still propagates as a genuine error.
     */
    private Mono<JsonNode> tuwunelRegister(String username, Map<String, Object> auth) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", username);
        body.put("password", svcPassword);
        if (auth != null) body.put("auth", auth);
        return tuwunel.post().uri("/_matrix/client/v3/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchangeToMono(resp -> {
                    int code = resp.statusCode().value();
                    if (resp.statusCode().is2xxSuccessful() || code == 400 || code == 401) {
                        return resp.bodyToMono(String.class)
                                .flatMap(ServiceTokenBroker::parseJson)
                                .switchIfEmpty(Mono.fromSupplier(JsonNodeFactory.instance::objectNode));
                    }
                    return resp.createException().flatMap(Mono::error);
                });
    }

    private Mono<JsonNode> tuwunelLogin(String username) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "m.login.password");
        body.put("identifier", Map.of("type", "m.id.user", "user", username));
        body.put("password", svcPassword);
        return postJson(tuwunel, "/_matrix/client/v3/login", body);
    }

    private static Map<String, Object> tokenOut(JsonNode n) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("access_token", n.path("access_token").asText());
        if (n.hasNonNull("user_id")) out.put("user_id", n.path("user_id").asText());
        return out;
    }

    private static Map<String, Object> toMap(JsonNode n) {
        Map<String, Object> out = new LinkedHashMap<>();
        n.properties().forEach(e -> out.put(e.getKey(),
                e.getValue().isTextual() ? e.getValue().asText() : e.getValue()));
        return out;
    }

    private Mono<JsonNode> postJson(WebClient client, String path, Object body) {
        return client.post().uri(path)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                // Boot 4's reactive JSON codec is Jackson 3 (tools.jackson) and
                // cannot decode into this Jackson-2 JsonNode; read the body as a
                // String (always codec-safe) and parse it with the Jackson-2 mapper.
                .bodyToMono(String.class)
                .flatMap(ServiceTokenBroker::parseJson)
                .switchIfEmpty(Mono.fromSupplier(JsonNodeFactory.instance::objectNode));
    }

    /**
     * Parse a homeserver JSON body with the Jackson-2 {@link #MAPPER}. A blank or
     * empty body yields an empty {@link Mono} so the caller's {@code switchIfEmpty}
     * supplies an empty object node (preserving the prior empty-response behaviour).
     */
    private static Mono<JsonNode> parseJson(String json) {
        if (json == null || json.isBlank()) {
            return Mono.empty();
        }
        try {
            return Mono.just(MAPPER.readTree(json));
        } catch (JsonProcessingException e) {
            return Mono.error(new RuntimeException(
                    "broker: invalid JSON response from homeserver", e));
        }
    }
}
