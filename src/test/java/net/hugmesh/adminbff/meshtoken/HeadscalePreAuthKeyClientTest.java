package net.hugmesh.adminbff.meshtoken;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The headscale pre-auth key leg against a real HTTP server standing in for headscale 0.23.
 *
 * <p>THE TAG GUARD: whatever the token grants, the key headscale is asked for carries
 * {@code aclTags} = exactly {@code ["tag:hugmesh"]}, and a response that claims other tags is
 * not believed. Also: user by name, single-use, non-ephemeral, expiry = the token's; the API key
 * is re-read per call (rotation); errors carry the status, never a body.
 */
class HeadscalePreAuthKeyClientTest {

    HttpServer server;
    final List<String> bodies = new CopyOnWriteArrayList<>();
    final List<String> auths = new CopyOnWriteArrayList<>();
    final AtomicInteger status = new AtomicInteger(200);
    final AtomicReference<String> reply = new AtomicReference<>();
    Path apiKey;
    HeadscalePreAuthKeyClient client;

    @BeforeEach
    void start(@TempDir Path dir) throws Exception {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/api/v1/preauthkey", ex -> {
            bodies.add(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            auths.add(ex.getRequestHeaders().getFirst("Authorization"));
            byte[] out = reply.get().getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(status.get(), out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        server.start();
        reply.set("""
                {"preAuthKey":{"user":"hugmesh","id":"42","key":"9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928",
                "reusable":false,"ephemeral":false,"used":false,"expiration":"2026-11-11T12:00:00Z",
                "createdAt":"2026-11-04T12:00:00Z","aclTags":["tag:superadmin","tag:dom_x"]}}""");
        apiKey = dir.resolve("admin-bff.apikey");
        Files.writeString(apiKey, "hskey-api-first\n");
        MeshTokenProperties p = new MeshTokenProperties();
        p.getHeadscale().setBaseUrl("http://127.0.0.1:" + server.getAddress().getPort());
        p.getHeadscale().setApiKeyPath(apiKey.toString());
        p.getHeadscale().setUser("hugmesh");
        p.getHeadscale().setTimeoutMs(5000);
        client = new HeadscalePreAuthKeyClient(p, WebClient.builder(), new ObjectMapper());
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void requestBody_tagsAreExactlyTagHugmesh_userByName_singleUse_expiresWithToken() throws Exception {
        Instant exp = Instant.parse("2026-11-11T12:00:00Z");
        HeadscalePreAuthKeyClient.PreAuthKey k = client.create(exp).block();
        assertThat(k.id()).isEqualTo("42");
        assertThat(k.key()).isEqualTo("9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928");

        JsonNode sent = new ObjectMapper().readTree(bodies.get(0));
        assertThat(sent.size()).as("no field beyond the five").isEqualTo(5);
        assertThat(sent.get("user").asText()).isEqualTo("hugmesh");
        assertThat(sent.get("reusable").asBoolean()).isFalse();
        assertThat(sent.get("ephemeral").asBoolean()).isFalse();
        assertThat(sent.get("expiration").asText()).isEqualTo("2026-11-11T12:00:00Z");
        assertThat(sent.get("aclTags").isArray()).isTrue();
        assertThat(sent.get("aclTags").size()).isEqualTo(1);
        assertThat(sent.get("aclTags").get(0).asText()).isEqualTo("tag:hugmesh");
        assertThat(auths.get(0)).isEqualTo("Bearer hskey-api-first");
    }

    @Test
    void theTagListIsAConstant_notDerivedFromAnyGrant() {
        assertThat(HeadscalePreAuthKeyClient.KEY_TAGS).containsExactly("tag:hugmesh");
        // the body builder takes nothing but the expiry: there is no way to pass a role or domain in
        assertThat(client.requestBody(Instant.EPOCH).get("aclTags")).isEqualTo(List.of("tag:hugmesh"));
        assertThat(client.requestBody(Instant.EPOCH).keySet())
                .containsExactly("user", "reusable", "ephemeral", "expiration", "aclTags");
    }

    @Test
    void responseTags_areNotTrusted_orEvenSurfaced() {
        HeadscalePreAuthKeyClient.PreAuthKey k = client.create(Instant.now().plusSeconds(60)).block();
        assertThat(HeadscalePreAuthKeyClient.PreAuthKey.class.getRecordComponents())
                .extracting(c -> c.getName()).containsExactly("id", "key");
        assertThat(k.toString()).doesNotContain(k.key()).contains("<redacted>");
    }

    @Test
    void apiKeyFile_isReReadOnEveryCall_soRotationNeedsNoRestart() throws Exception {
        client.create(Instant.now().plusSeconds(60)).block();
        Files.writeString(apiKey, "hskey-api-rotated");
        client.create(Instant.now().plusSeconds(60)).block();
        assertThat(auths).containsExactly("Bearer hskey-api-first", "Bearer hskey-api-rotated");
    }

    @Test
    void missingApiKeyFile_failsWithASentence_andNoRequest() throws Exception {
        Files.delete(apiKey);
        assertThatThrownBy(() -> client.create(Instant.now().plusSeconds(60)).block())
                .isInstanceOf(HeadscalePreAuthKeyClient.HeadscaleUnavailableException.class)
                .hasMessageContaining("cannot be read yet");
        assertThat(bodies).isEmpty();
    }

    @Test
    void httpError_reportsTheStatusOnly_neverTheBody() {
        status.set(500);
        reply.set("{\"code\":2,\"message\":\"secret-looking-echo hskey-api-first\"}");
        assertThatThrownBy(() -> client.create(Instant.now().plusSeconds(60)).block())
                .isInstanceOf(HeadscalePreAuthKeyClient.HeadscaleUnavailableException.class)
                .hasMessageContaining("HTTP 500")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("secret-looking-echo")
                        .doesNotContain("hskey-api-first"));
    }

    @Test
    void responseWithoutAKey_isRefused() {
        reply.set("{\"preAuthKey\":{\"id\":\"1\"}}");
        assertThatThrownBy(() -> client.create(Instant.now().plusSeconds(60)).block())
                .isInstanceOf(HeadscalePreAuthKeyClient.HeadscaleUnavailableException.class)
                .hasMessageContaining("no usable pre-auth key");
        reply.set("{\"preAuthKey\":{\"id\":\"1\",\"key\":\"has\\\"quote\"}}");
        assertThatThrownBy(() -> client.create(Instant.now().plusSeconds(60)).block())
                .isInstanceOf(HeadscalePreAuthKeyClient.HeadscaleUnavailableException.class);
    }
}
