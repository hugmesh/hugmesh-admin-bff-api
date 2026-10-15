package net.hugmesh.adminbff.notification.channel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.notification.SystemChannelTokens;

import java.time.Duration;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * The REAL Akkoma {@code @system} direct-notice transport (Notifications external
 * channels, Akkoma leg). It posts as the {@code @system} account with that account's own
 * access token over the plain Mastodon-API, NOT with the admin bearer the announcement
 * client uses: a notice is an ordinary status by an ordinary (least-privilege) account.
 *
 * <h3>Wire sequence</h3>
 * <ol>
 *   <li>{@code GET /api/v1/accounts/lookup?acct={localpart}} — <b>existence probe</b>. A
 *       {@code direct} status that @-mentions a name nobody owns is still created and
 *       reaches no one, so without the probe a user with no Akkoma account would be
 *       recorded {@code sent}. 404 is the terminal {@link ChannelOutcome#SKIPPED}.</li>
 *   <li>{@code POST /api/v1/statuses} with {@code visibility=direct} and a body that
 *       starts with the {@code @localpart} mention. A bare local name (no
 *       {@code @domain}) cannot federate, so the notice stays on this instance.</li>
 * </ol>
 *
 * <h3>Idempotent retry</h3>
 * The {@code Idempotency-Key} header is derived from the outbox row id
 * ({@link ChannelMessage#deliveryKey()}); Akkoma replays the first response for a repeated
 * key instead of posting a second status (assumed from the API documentation; see below).
 *
 * <h3>Outcome mapping</h3>
 * Covered by tests (against the fake server): a transport error (server down), a bad or
 * absent token, a 5xx on the lookup, and a 422 or 503 on the post each resolve to
 * {@link ChannelOutcome#FAILED} (retry). A lookup 404, or an invalid localpart, is the
 * terminal SKIP.
 * <p>NOT covered by any test: a timeout, and a malformed or non-JSON body. A 2xx reply to
 * the post is trusted by its status alone: a body that does not parse is ignored, so a 200
 * with a non-JSON body (a captive portal page, say) is returned as {@link ChannelOutcome#SENT}.
 * No test captures the log output, so nothing here proves what is or is not logged.
 *
 * <p><b>Verification status.</b> The Mastodon-API shapes used here are the standard ones, and
 * the fake server in the tests encodes them, but no Akkoma instance was available to run
 * them against. Treat the {@code lookup} 404 and the {@code Idempotency-Key} replay as
 * UNCONFIRMED against a real Akkoma: no live test exists for Akkoma.
 *
 * <p>Ships dark: the bean exists only when {@code notify.akkoma.notice.wired=true}.
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns these singleton collaborators and they are never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class AkkomaSystemNoticeClient {

    private static final Logger log = LoggerFactory.getLogger(AkkomaSystemNoticeClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Pattern LOCALPART = Pattern.compile("[a-z0-9._-]+");
    private static final Pattern KEY_UNSAFE = Pattern.compile("[^A-Za-z0-9_-]");
    private static final int MAX_LOCALPART = 64;
    /** Akkoma's default {@code max_toot_chars} is 5000 (Mastodon: 500); stay well inside it. */
    static final int MAX_STATUS_CHARS = 4000;

    private final WebClient http;
    private final SystemChannelTokens tokens;
    private final Duration timeout;

    public AkkomaSystemNoticeClient(WebClient http, SystemChannelTokens tokens, Duration timeout) {
        this.http = http;
        this.tokens = tokens;
        this.timeout = timeout;
    }

    private record Reply(int status, JsonNode body) {
        boolean ok() {
            return status >= 200 && status < 300;
        }
    }

    public Mono<ChannelOutcome> sendDirectNotice(String localpart, String text, String deliveryKey) {
        String lp = localpart == null ? "" : localpart.trim();
        if (lp.isEmpty() || lp.length() > MAX_LOCALPART || !LOCALPART.matcher(lp).matches()) {
            return Mono.just(ChannelOutcome.SKIPPED);
        }
        String token = tokens.akkoma().orElse(null);
        if (token == null) {
            return Mono.just(ChannelOutcome.FAILED);
        }
        String key = deliveryKey == null || deliveryKey.isBlank()
                ? UUID.randomUUID().toString()
                : "hm-" + KEY_UNSAFE.matcher(deliveryKey).replaceAll("_");
        return lookup(token, lp)
                .flatMap(r -> afterLookup(r, token, lp, text, key))
                .onErrorResume(e -> {
                    log.warn("[notify-akkoma] notice to '{}' failed (retry next tick): {}", lp, e.toString());
                    return Mono.just(ChannelOutcome.FAILED);
                })
                .defaultIfEmpty(ChannelOutcome.FAILED);
    }

    private Mono<ChannelOutcome> afterLookup(Reply r, String token, String lp, String text, String key) {
        if (r.status() == 404) {
            log.debug("[notify-akkoma] '{}' has no akkoma account; SKIPPED", lp);
            return Mono.just(ChannelOutcome.SKIPPED);
        }
        if (!r.ok()) {
            return Mono.just(failed("account lookup", lp, r.status()));
        }
        return post(token, lp, text, key)
                .map(p -> p.ok() ? ChannelOutcome.SENT : failed("status post", lp, p.status()));
    }

    private Mono<Reply> lookup(String token, String lp) {
        return http.get().uri("/api/v1/accounts/lookup?acct={acct}", lp)
                .headers(h -> h.setBearerAuth(token))
                .accept(MediaType.APPLICATION_JSON)
                .exchangeToMono(this::toReply)
                .timeout(timeout);
    }

    private Mono<Reply> post(String token, String lp, String text, String key) {
        String status = "@" + lp + " " + (text == null ? "" : text);
        if (status.length() > MAX_STATUS_CHARS) {
            status = status.substring(0, MAX_STATUS_CHARS - 1) + "…";
        }
        ObjectNode body = MAPPER.createObjectNode();
        body.put("status", status);
        body.put("visibility", "direct");
        // Serialised here and sent as a String: the WebClient codecs are Jackson 3 and do
        // not encode a Jackson 2 tree (see MatrixSystemDmClient).
        return http.post().uri("/api/v1/statuses")
                .headers(h -> {
                    h.setBearerAuth(token);
                    h.set("Idempotency-Key", key);
                })
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(body.toString())
                .exchangeToMono(this::toReply)
                .timeout(timeout);
    }

    private Mono<Reply> toReply(org.springframework.web.reactive.function.client.ClientResponse resp) {
        return resp.bodyToMono(String.class).defaultIfEmpty("")
                .map(raw -> new Reply(resp.statusCode().value(), parse(raw)));
    }

    private static JsonNode parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return MAPPER.readTree(raw);
        } catch (Exception e) {
            return null;
        }
    }

    private static ChannelOutcome failed(String what, String lp, int status) {
        log.warn("[notify-akkoma] {} for '{}' HTTP {} (retry next tick)", what, lp, status);
        return ChannelOutcome.FAILED;
    }
}
