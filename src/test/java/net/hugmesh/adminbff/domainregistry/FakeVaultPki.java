package net.hugmesh.adminbff.domainregistry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A real loopback HTTP server playing the four Vault endpoints the CA effector calls — the
 * in-repo stand-in for a MockWebServer (same JDK {@code HttpServer} idiom as
 * {@code FakeMatrixHomeserver}), so the client under test goes through its real
 * {@code WebClient} and socket path. Behaviour follows Vault's documented answers:
 * <ul>
 *   <li>{@code GET /v1/sys/mounts/<m>} — 200 {@code {"type":..,"data":{"type":..}}} when
 *       mounted, 400 {@code "No secret engine mount at <m>/"} when not;</li>
 *   <li>{@code POST /v1/sys/mounts/<m>} — 204, or 400 "path is already in use" when mounted;</li>
 *   <li>{@code LIST <m>/issuers} ({@code GET ...?list=true}) — 200 with {@code data.keys}, or
 *       404 when the mount has no issuer;</li>
 *   <li>{@code POST /v1/<m>/root/generate/internal} — 200 with a certificate and NO key.</li>
 * </ul>
 * Any request without the expected token is answered 403 {@code permission denied}. A forced
 * status per {@code "METHOD path-suffix"} overrides the handling for fault injection.
 */
final class FakeVaultPki implements AutoCloseable {

    static final String TOKEN = "hvs.test-only-token";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    record Seen(String method, String path, String query, String token, JsonNode body) { }

    final List<Seen> requests = Collections.synchronizedList(new ArrayList<>());
    /** mount path -> engine type. */
    final Map<String, String> mounts = new HashMap<>();
    /** mounts holding at least one issuer. */
    final Set<String> rooted = new HashSet<>();
    final Map<String, Integer> forcedStatus = new HashMap<>();
    private final HttpServer server;

    FakeVaultPki() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    long count(String method, String pathSuffix) {
        synchronized (requests) {
            return requests.stream()
                    .filter(r -> r.method().equals(method) && r.path().endsWith(pathSuffix)).count();
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange ex) throws IOException {
        String m = ex.getRequestMethod();
        String path = ex.getRequestURI().getPath();
        String query = ex.getRequestURI().getQuery();
        String token = ex.getRequestHeaders().getFirst("X-Vault-Token");
        String raw = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        JsonNode body = raw.isBlank() ? MAPPER.createObjectNode() : MAPPER.readTree(raw);
        requests.add(new Seen(m, path, query, token, body));

        for (Map.Entry<String, Integer> f : forcedStatus.entrySet()) {
            String[] mp = f.getKey().split(" ", 2);
            if (mp[0].equals(m) && path.endsWith(mp[1])) {
                reply(ex, f.getValue(), "{\"errors\":[\"forced\"]}");
                return;
            }
        }
        if (!TOKEN.equals(token)) {
            reply(ex, 403, "{\"errors\":[\"permission denied\"]}");
            return;
        }
        if (path.startsWith("/v1/sys/mounts/")) {
            String mount = path.substring("/v1/sys/mounts/".length());
            if ("GET".equals(m)) {
                String type = mounts.get(mount);
                if (type == null) {
                    reply(ex, 400, "{\"errors\":[\"No secret engine mount at " + mount + "/\"]}");
                } else {
                    reply(ex, 200, "{\"type\":\"" + type + "\",\"data\":{\"type\":\"" + type + "\"}}");
                }
                return;
            }
            if ("POST".equals(m)) {
                if (mounts.containsKey(mount)) {
                    reply(ex, 400, "{\"errors\":[\"path is already in use at " + mount + "/\"]}");
                } else {
                    mounts.put(mount, body.path("type").asText());
                    reply(ex, 204, "");
                }
                return;
            }
        }
        if ("GET".equals(m) && path.endsWith("/issuers") && "list=true".equals(query)) {
            String mount = path.substring("/v1/".length(), path.length() - "/issuers".length());
            if (rooted.contains(mount)) {
                reply(ex, 200, "{\"data\":{\"keys\":[\"8f0e5a2c-0000-4000-8000-000000000001\"]}}");
            } else {
                reply(ex, 404, "{\"errors\":[]}");
            }
            return;
        }
        if ("POST".equals(m) && path.endsWith("/root/generate/internal")) {
            String mount = path.substring("/v1/".length(), path.length() - "/root/generate/internal".length());
            if (!"pki".equals(mounts.get(mount))) {
                reply(ex, 404, "{\"errors\":[\"no handler for route\"]}");
                return;
            }
            rooted.add(mount);
            reply(ex, 200, "{\"data\":{\"certificate\":\"-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\","
                    + "\"issuer_id\":\"8f0e5a2c-0000-4000-8000-000000000001\",\"serial_number\":\"01\"}}");
            return;
        }
        reply(ex, 404, "{\"errors\":[]}");
    }

    private static void reply(HttpExchange ex, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        if (status == 204 || bytes.length == 0) {
            ex.sendResponseHeaders(status, -1);
            ex.close();
            return;
        }
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
