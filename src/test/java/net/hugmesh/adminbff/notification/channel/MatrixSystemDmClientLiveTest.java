package net.hugmesh.adminbff.notification.channel;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.adminbff.notification.SystemChannelTokens;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The same contract as {@link MatrixSystemDmClientTest}, against a REAL homeserver. Skipped
 * unless {@code MATRIX_LIVE_URL} is set, so CI and a plain {@code mvn test} never need one.
 *
 * <p>The homeserver must allow open registration with the dummy auth stage (a throwaway
 * tuwunel does; do NOT point this at a mesh):
 * <pre>
 *   docker run -d --rm --name tw -p 127.0.0.1:18008:8008 --tmpfs /var/lib/tuwunel \
 *     -e TUWUNEL_SERVER_NAME=probe.test -e TUWUNEL_ADDRESS=0.0.0.0 -e TUWUNEL_PORT=8008 \
 *     -e TUWUNEL_DATABASE_PATH=/var/lib/tuwunel -e TUWUNEL_ALLOW_REGISTRATION=true \
 *     -e TUWUNEL_YES_I_AM_VERY_VERY_SURE_I_WANT_AN_OPEN_REGISTRATION_SERVER_PRONE_TO_ABUSE=true \
 *     -e TUWUNEL_ALLOW_FEDERATION=false ghcr.io/matrix-construct/tuwunel:v1.7.0
 *   MATRIX_LIVE_URL=http://127.0.0.1:18008 ./mvnw -o -Dtest=MatrixSystemDmClientLiveTest test
 * </pre>
 * It registers fresh {@code system-*}/{@code user-*} accounts per run, so it can be re-run.
 */
@EnabledIfEnvironmentVariable(named = "MATRIX_LIVE_URL", matches = ".+")
class MatrixSystemDmClientLiveTest {

    private static final String URL = System.getenv("MATRIX_LIVE_URL");

    private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();

    /** Parse with Jackson 2 here: the WebClient codecs are Jackson 3 and cannot decode a
     *  Jackson 2 {@link JsonNode}. */
    private static JsonNode tree(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static JsonNode register(WebClient http, String user) {
        return tree(http.post().uri("/_matrix/client/v3/register").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("username", user, "password", "pw-" + user + "-" + UUID.randomUUID(),
                        "auth", Map.of("type", "m.login.dummy")))
                .retrieve().bodyToMono(String.class).block(Duration.ofSeconds(10)));
    }

    @Test
    void dm_isDelivered_deduped_reused_andAnUnknownUserIsSkipped() {
        WebClient http = WebClient.builder().baseUrl(URL).build();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        JsonNode system = register(http, "system-" + suffix);
        String userLocal = "user-" + suffix;
        JsonNode user = register(http, userLocal);
        MatrixSystemDmClient c = new MatrixSystemDmClient(http,
                new SystemChannelTokens(system.get("access_token").asText(), "", "", ""), Duration.ofSeconds(10));

        assertThat(c.sendDirectMessage(userLocal, "Title\n\nBody", "live-1").block()).isEqualTo(ChannelOutcome.SENT);
        // same key again (a retry after a lost reply): accepted, not duplicated
        assertThat(c.sendDirectMessage(userLocal, "Title\n\nBody", "live-1").block()).isEqualTo(ChannelOutcome.SENT);
        assertThat(c.sendDirectMessage(userLocal, "Second", "live-2").block()).isEqualTo(ChannelOutcome.SENT);
        assertThat(c.cachedRooms()).hasSize(1);

        // the recipient joins the DM and sees exactly the two distinct messages, from @system
        String room = c.cachedRooms().values().iterator().next();
        String token = user.get("access_token").asText();
        http.post().uri("/_matrix/client/v3/rooms/{r}/join", room).headers(h -> h.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of()).retrieve()
                .toBodilessEntity().block(Duration.ofSeconds(10));
        JsonNode msgs = tree(http.get().uri("/_matrix/client/v3/rooms/{r}/messages?dir=b&limit=50", room)
                .headers(h -> h.setBearerAuth(token)).retrieve().bodyToMono(String.class)
                .block(Duration.ofSeconds(10)));
        long texts = 0;
        for (JsonNode e : msgs.get("chunk")) {
            if ("m.room.message".equals(e.get("type").asText())) {
                texts++;
                assertThat(e.get("sender").asText()).startsWith("@system-" + suffix + ":");
                assertThat(e.get("content").get("msgtype").asText()).isEqualTo("m.text");
            }
        }
        assertThat(texts).isEqualTo(2);

        // an account that does not exist: skipped, even though createRoom would have said 200
        assertThat(c.sendDirectMessage("nobody-" + suffix, "x", "live-3").block()).isEqualTo(ChannelOutcome.SKIPPED);
    }
}
