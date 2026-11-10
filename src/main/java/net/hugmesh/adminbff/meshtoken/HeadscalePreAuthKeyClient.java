package net.hugmesh.adminbff.meshtoken;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * Mints ONE single-use headscale pre-auth key per issued token, over headscale 0.23's REST API
 * ({@code POST /api/v1/preauthkey}).
 *
 * <h2>The tags are not a parameter</h2>
 * The request carries {@code aclTags} = {@link #KEY_TAGS}, exactly {@code ["tag:hugmesh"]},
 * and there is no argument through which a caller could add one. A pre-auth key may carry only
 * {@code tag:hugmesh} plus node role tags; a token's role and domain are NOT key tags — the mesh
 * policy decides those ({@code dom_/mesh_/dev_/superadmin} are server-forced). Mapping the
 * token's role to a key tag would let anybody holding an ADMIN session mint a
 * {@code tag:superadmin} node.
 *
 * <p>The 0.23 create response echoes {@code aclTags}; it is NOT read back or trusted. Only the
 * {@code key} (handed into the token, never logged or stored) and the numeric {@code id} (the
 * audit row's {@code preauth_key_id}) are taken from it.
 *
 * <h2>API key custody</h2>
 * headscale 0.23 API keys are unscoped admin keys. The key lives only in a file mounted into
 * this service ({@code app.mesh-token.headscale.api-key-path}: a docker volume locally, a Vault
 * secret volume in-cluster), is re-read on every call so a rotation needs no restart, and is sent
 * only as a Bearer header to {@code base-url}, which is reachable only on the compose network /
 * as a ClusterIP. This class calls only {@code POST /api/v1/preauthkey}.
 */
@Component
public class HeadscalePreAuthKeyClient {

    private static final Logger log = LoggerFactory.getLogger(HeadscalePreAuthKeyClient.class);

    static final String PATH = "/api/v1/preauthkey";
    /** The ONLY tags a token's pre-auth key ever carries. */
    static final List<String> KEY_TAGS = List.of("tag:hugmesh");

    private final MeshTokenProperties props;
    private final WebClient http;
    private final ObjectMapper mapper;

    public HeadscalePreAuthKeyClient(MeshTokenProperties props, WebClient.Builder builder, ObjectMapper mapper) {
        this.props = props;
        this.http = builder.clone().baseUrl(props.getHeadscale().getBaseUrl()).build();
        this.mapper = mapper;
    }

    /** A minted key. {@link #toString()} never prints {@code key}. */
    public record PreAuthKey(String id, String key) {
        @Override
        public String toString() {
            return "PreAuthKey[id=" + id + ", key=<redacted>]";
        }
    }

    /** Headscale could not mint a key; the message is a sentence for the operator, never a secret. */
    public static final class HeadscaleUnavailableException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public HeadscaleUnavailableException(String message) {
            super(message, null, false, false);
        }
    }

    /** The request body, built in one place so the tag guard is testable without a server. */
    Map<String, Object> requestBody(Instant expiration) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("user", props.getHeadscale().getUser());
        body.put("reusable", false);
        body.put("ephemeral", false);
        body.put("expiration", Instant.ofEpochSecond(expiration.getEpochSecond()).toString());
        body.put("aclTags", KEY_TAGS);
        return body;
    }

    /** Mint a single-use, non-ephemeral key that expires with the token. */
    public Mono<PreAuthKey> create(Instant expiration) {
        String apiKey;
        try {
            apiKey = readApiKey();
        } catch (HeadscaleUnavailableException e) {
            return Mono.error(e);
        }
        Duration timeout = Duration.ofMillis(props.getHeadscale().getTimeoutMs() > 0
                ? props.getHeadscale().getTimeoutMs() : 8000);
        return http.post()
                .uri(PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .headers(h -> h.setBearerAuth(apiKey))
                .bodyValue(requestBody(expiration))
                .retrieve()
                .bodyToMono(String.class)
                .timeout(timeout)
                .onErrorMap(e -> !(e instanceof HeadscaleUnavailableException), this::describe)
                .flatMap(body -> Mono.fromCallable(() -> parse(body)));
    }

    PreAuthKey parse(String body) {
        JsonNode root;
        try {
            root = mapper.readTree(body == null ? "" : body);
        } catch (IOException e) {
            throw new HeadscaleUnavailableException("headscale answered the pre-auth key request with "
                    + "something that is not JSON.");
        }
        JsonNode k = root == null ? null : root.path("preAuthKey");
        if (k == null || k.isMissingNode() || k.isNull()) {
            k = root == null ? null : root.path("pre_auth_key");
        }
        String key = k == null ? "" : k.path("key").asText("");
        String id = k == null ? "" : k.path("id").asText("");
        if (key.isEmpty() || !MeshTokenPayload.safeAscii(key) || key.chars().anyMatch(c -> c == ' ')) {
            throw new HeadscaleUnavailableException("headscale created no usable pre-auth key.");
        }
        if (!id.matches("^[0-9]{1,20}$")) {
            id = "";
        }
        log.info("[mesh-token] headscale minted pre-auth key id={} (single-use, tags fixed to {})", id, KEY_TAGS);
        return new PreAuthKey(id, key);
    }

    private String readApiKey() {
        String p = props.getHeadscale().getApiKeyPath();
        if (p == null || p.isBlank()) {
            throw new HeadscaleUnavailableException("No headscale API key is configured "
                    + "(app.mesh-token.headscale.api-key-path).");
        }
        String key;
        try {
            key = Files.readString(Path.of(p), StandardCharsets.US_ASCII).trim();
        } catch (IOException e) {
            throw new HeadscaleUnavailableException("The headscale API key file " + p
                    + " cannot be read yet; is headscale running?");
        }
        if (key.isEmpty() || !MeshTokenPayload.safeAscii(key) || key.contains(" ")) {
            throw new HeadscaleUnavailableException("The headscale API key file " + p + " holds no usable key.");
        }
        return key;
    }

    private Throwable describe(Throwable e) {
        // Status code and class only: a response body or exception message could quote a key.
        if (e instanceof WebClientResponseException w) {
            log.warn("[mesh-token] headscale POST {} answered HTTP {}", PATH, w.getStatusCode().value());
            return new HeadscaleUnavailableException("headscale refused to create the pre-auth key (HTTP "
                    + w.getStatusCode().value() + ").");
        }
        if (e instanceof TimeoutException) {
            log.warn("[mesh-token] headscale POST {} timed out", PATH);
            return new HeadscaleUnavailableException("headscale did not answer in time.");
        }
        log.warn("[mesh-token] headscale POST {} failed: {}", PATH, e.getClass().getSimpleName());
        return new HeadscaleUnavailableException("headscale could not be reached at "
                + props.getHeadscale().getBaseUrl() + ".");
    }
}
