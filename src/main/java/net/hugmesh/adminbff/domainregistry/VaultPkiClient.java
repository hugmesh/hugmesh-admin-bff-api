package net.hugmesh.adminbff.domainregistry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;
import java.util.regex.Pattern;

/**
 * The Vault PKI calls behind the per-domain CA effector (hugmesh-admin-bff-api#99). Four
 * requests, each answered by a documented Vault HTTP status:
 *
 * <ol>
 *   <li>{@code GET /v1/sys/mounts/<mount>} — 200 with {@code type=pki}: already mounted;
 *       200 with another type: the path is taken by a different engine (FAILURE, never
 *       re-used); 400/404: not mounted yet;</li>
 *   <li>{@code POST /v1/sys/mounts/<mount>} {@code {"type":"pki",...}} — enable the engine
 *       (only when step 1 found nothing);</li>
 *   <li>{@code GET /v1/<mount>/issuers?list=true} — 200 with keys: a root already exists
 *       (a previous pass generated it but did not get to record it), so it is REUSED rather
 *       than a second root minted; 404: no issuer yet;</li>
 *   <li>{@code POST /v1/<mount>/root/generate/internal} — mint the self-signed root.</li>
 * </ol>
 *
 * <h3>Key material</h3>
 * Step 4 uses the {@code internal} generation type, the one under which Vault keeps the
 * private key and never returns it — the {@code exported} type would put the key bytes in
 * the response. The response body (certificate and issuer ids only) is released unread, and
 * no request or response body is ever logged. The token travels only in the
 * {@code X-Vault-Token} header and appears in no exception message.
 *
 * <p>Any status outside the ones listed above is a {@link VaultPkiException} naming the step
 * and the HTTP status — nothing from the response body is copied into it.
 */
public class VaultPkiClient {

    /** A mount path this client is willing to put into a Vault URL: one plain path segment. */
    private static final Pattern MOUNT_PATH = Pattern.compile("^[a-z0-9][a-z0-9_-]{0,126}$");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The step of {@link #ensureRoot} a failure happened in. */
    public enum Step { READ_MOUNT, ENABLE_MOUNT, LIST_ISSUERS, GENERATE_ROOT }

    /** What {@link #ensureRoot} found or did. */
    public record RootResult(String mountPath, boolean mountCreated, boolean rootGenerated) { }

    /** A Vault answer outside the expected set for its step. Carries no response body. */
    public static final class VaultPkiException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final Step step;
        private final int status;

        public VaultPkiException(Step step, int status, String reason) {
            super("vault " + step + " answered HTTP " + status + (reason == null ? "" : " (" + reason + ")"));
            this.step = step;
            this.status = status;
        }

        public Step step() { return step; }
        public int status() { return status; }
    }

    /** Root parameters from {@link DomainCaProperties}. */
    public record RootSpec(String maxLeaseTtl, String rootTtl, String keyType, int keyBits,
                           int signatureBits) {
        static RootSpec of(DomainCaProperties p) {
            return new RootSpec(p.getMaxLeaseTtl(), p.getRootTtl(), p.getKeyType(),
                    p.getKeyBits(), p.getSignatureBits());
        }
    }

    private final WebClient http;
    private final RootSpec spec;
    private final Duration timeout;

    /** Production constructor: the outbound (cluster-CA-trusting) reactor-netty client. */
    public VaultPkiClient(String vaultAddr, String token, RootSpec spec, long timeoutMs,
                          HttpClient httpClient) {
        this(WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .baseUrl(vaultAddr)
                .defaultHeader("X-Vault-Token", token == null ? "" : token)
                .build(), spec, timeoutMs);
    }

    /** Test seam — a pre-built WebClient (base URL and token header already applied). */
    VaultPkiClient(WebClient http, RootSpec spec, long timeoutMs) {
        this.http = http;
        this.spec = spec;
        this.timeout = Duration.ofMillis(timeoutMs);
    }

    /** Whether {@code mountPath} is a single safe path segment this client will call. */
    public static boolean isValidMountPath(String mountPath) {
        return mountPath != null && MOUNT_PATH.matcher(mountPath).matches();
    }

    /**
     * Make sure {@code mountPath} is a PKI engine holding a self-signed root, creating
     * whatever is missing. Idempotent: re-running after a partial success (mount made, root
     * not; or root made, row not recorded) completes the work without a second root.
     */
    public Mono<RootResult> ensureRoot(String mountPath, String commonName) {
        if (!isValidMountPath(mountPath)) {
            return Mono.error(new IllegalArgumentException(
                    "refusing Vault PKI mount path '" + mountPath + "': not a single lowercase path segment"));
        }
        return mountState(mountPath)
                .flatMap(mounted -> (mounted ? Mono.just(false) : enableMount(mountPath).thenReturn(true))
                        .flatMap(created -> hasIssuer(mountPath)
                                .flatMap(has -> has
                                        ? Mono.just(new RootResult(mountPath, created, false))
                                        : generateRoot(mountPath, commonName)
                                                .thenReturn(new RootResult(mountPath, created, true)))));
    }

    /** Step 1: true when a PKI engine is already mounted there, false when nothing is. */
    private Mono<Boolean> mountState(String mountPath) {
        return http.get().uri("/v1/sys/mounts/{mount}", mountPath)
                .exchangeToMono(VaultPkiClient::mountStateFrom)
                .timeout(timeout);
    }

    /** Step 1's answer: 200 names the engine there, 400/404 means nothing is mounted. */
    private static Mono<Boolean> mountStateFrom(ClientResponse r) {
        int code = r.statusCode().value();
        if (r.statusCode().is2xxSuccessful()) {
            return r.bodyToMono(String.class).defaultIfEmpty("{}").flatMap(body -> {
                String type = engineType(body);
                return "pki".equals(type)
                        ? Mono.just(true)
                        : Mono.<Boolean>error(new VaultPkiException(Step.READ_MOUNT, code,
                                "path is already mounted as a '" + type + "' engine, not pki"));
            });
        }
        if (code == 400 || code == 404) {
            return r.releaseBody().thenReturn(false);
        }
        return failure(r, Step.READ_MOUNT);
    }

    /** Step 2: enable a PKI engine at the mount path. */
    private Mono<Void> enableMount(String mountPath) {
        ObjectNode body = MAPPER.createObjectNode().put("type", "pki")
                .put("description", "hugmesh per-domain root CA (admin-bff domain registry)");
        body.putObject("config").put("max_lease_ttl", spec.maxLeaseTtl());
        return post("/v1/sys/mounts/" + mountPath, body, Step.ENABLE_MOUNT);
    }

    /** Step 3: whether the mount already holds at least one issuer. */
    private Mono<Boolean> hasIssuer(String mountPath) {
        return http.get().uri(uri -> uri.path("/v1/" + mountPath + "/issuers").queryParam("list", "true").build())
                .exchangeToMono(r -> {
                    int code = r.statusCode().value();
                    if (r.statusCode().is2xxSuccessful()) {
                        return r.bodyToMono(String.class).defaultIfEmpty("{}").map(VaultPkiClient::hasKeys);
                    }
                    if (code == 404) {
                        return r.releaseBody().thenReturn(false);
                    }
                    return failure(r, Step.LIST_ISSUERS);
                })
                .timeout(timeout);
    }

    /** Step 4: generate the self-signed root with the key kept INSIDE Vault. */
    private Mono<Void> generateRoot(String mountPath, String commonName) {
        ObjectNode body = MAPPER.createObjectNode()
                .put("common_name", commonName)
                .put("issuer_name", "root")
                .put("ttl", spec.rootTtl())
                .put("key_type", spec.keyType())
                .put("key_bits", spec.keyBits())
                .put("signature_bits", spec.signatureBits());
        return post("/v1/" + mountPath + "/root/generate/internal", body, Step.GENERATE_ROOT);
    }

    private Mono<Void> post(String path, ObjectNode body, Step step) {
        String json;
        try {
            json = MAPPER.writeValueAsString(body);
        } catch (Exception e) {
            return Mono.error(new IllegalStateException("could not encode the Vault request for " + step, e));
        }
        return http.post().uri(path)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(json)
                .exchangeToMono(r -> r.statusCode().is2xxSuccessful()
                        // Released unread: for GENERATE_ROOT it carries the certificate, which is
                        // public, but nothing from a Vault response body is kept or logged.
                        ? r.releaseBody()
                        : failure(r, step))
                .timeout(timeout);
    }

    private static <T> Mono<T> failure(ClientResponse r, Step step) {
        HttpStatusCode status = r.statusCode();
        return r.releaseBody().then(Mono.error(new VaultPkiException(step, status.value(), null)));
    }

    private static String engineType(String body) {
        JsonNode n = parse(body);
        JsonNode type = n.path("data").path("type");
        if (type.isMissingNode() || type.isNull()) {
            type = n.path("type");
        }
        return type.asText("");
    }

    private static boolean hasKeys(String body) {
        JsonNode keys = parse(body).path("data").path("keys");
        return keys.isArray() && !keys.isEmpty();
    }

    private static JsonNode parse(String body) {
        try {
            return MAPPER.readTree(body);
        } catch (Exception e) {
            return MAPPER.createObjectNode();
        }
    }
}
