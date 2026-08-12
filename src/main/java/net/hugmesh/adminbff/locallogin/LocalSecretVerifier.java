package net.hugmesh.adminbff.locallogin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * REAL Casdoor credential oracle for the passwordless local-secrets login. It answers a
 * single yes/no question — "is this {@code username}+{@code secret} a valid Casdoor
 * credential?" — by performing the OAuth2 <b>Resource-Owner-Password-Credentials</b> grant
 * ({@code grant_type=password}) against the Casdoor token endpoint
 * ({@code {base}/api/login/oauth/access_token}), authenticating with the admin-bff
 * application's {@code client_id}/{@code client_secret}. Casdoor mints a token ONLY when the
 * supplied credential is genuinely correct, so a successful token response is proof of a valid
 * credential; the returned token itself is DISCARDED (the BFF mints its own opaque {@code bff_}
 * session — Casdoor is used purely as the credential authority, never as a token source that
 * reaches the browser).
 *
 * <p>This is the ONE piece the {@code /bff/login} password path never needed (that path trusts
 * the fronting gateway's validated Casdoor session/JWT). {@code /bff/login/local} is reached
 * pre-token from the loopback agent, so it MUST validate the secret itself — this class is that
 * validation, with NO bypass and NO trust of the agent.
 *
 * <h3>Fail-closed</h3>
 * Every non-success maps to {@code false} (invalid): a blank username/secret, a Casdoor
 * {@code {error}} body, a 4xx/5xx from Casdoor (bad credential), or any transport error. The
 * verify method NEVER throws through as valid and NEVER logs the secret or the form body.
 *
 * <p>Wired only when {@code app.local-login.enabled=true} ({@link LocalLoginConfig}); when the
 * bean is absent the controller injects {@code @Nullable ... = null} and the endpoint 401s
 * (fail-closed — no local-login trust surface exists until it is explicitly enabled AND Casdoor
 * is configured).
 */
public class LocalSecretVerifier {

    private static final Logger log = LoggerFactory.getLogger(LocalSecretVerifier.class);

    private final WebClient http;
    private final String tokenPath;
    private final String clientId;
    private final String clientSecret;

    public LocalSecretVerifier(String casdoorBaseUrl, String tokenPath,
                               String clientId, String clientSecret) {
        this(WebClient.builder().baseUrl(casdoorBaseUrl).build(), tokenPath, clientId, clientSecret);
    }

    /** Test seam — inject a pre-built WebClient (e.g. backed by a stub exchange). */
    LocalSecretVerifier(WebClient http, String tokenPath, String clientId, String clientSecret) {
        this.http = http;
        this.tokenPath = tokenPath;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /**
     * Validate {@code username}+{@code secret} against Casdoor. Emits {@code true} iff Casdoor
     * returns a token for the resource-owner-password grant; {@code false} for every failure
     * mode (blank input, {@code {error}} body, 4xx/5xx, transport error). Never throws.
     */
    public Mono<Boolean> verify(String username, String secret) {
        if (username == null || username.isBlank() || secret == null || secret.isEmpty()) {
            return Mono.just(false);
        }
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("username", username);
        form.add("password", secret);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        return http.post()
                .uri(tokenPath)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(Map.class)
                .map(LocalSecretVerifier::isValidTokenResponse)
                .defaultIfEmpty(false)
                .onErrorResume(e -> {
                    // Bad credentials surface as a 4xx (WebClientResponseException) or an {error}
                    // body; a transport hiccup is fail-closed. NEVER log the secret/form — only the
                    // exception type/message (which carries no credential).
                    log.debug("[local-login] casdoor password-grant verify rejected (treated as invalid): {}",
                            e.toString());
                    return Mono.just(false);
                });
    }

    /** A token response is valid iff it carries no {@code error} and a non-blank access token. */
    private static boolean isValidTokenResponse(Map<?, ?> body) {
        if (body == null || body.get("error") != null) {
            return false;
        }
        Object token = body.get("access_token");
        return token != null && !token.toString().isBlank();
    }
}
