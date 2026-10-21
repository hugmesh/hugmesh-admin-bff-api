package net.hugmesh.adminbff.notification.channel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.notification.SystemChannelTokens;

import java.time.Duration;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * The phpBB {@code @system} private-message transport (Notifications external channels,
 * forum leg). It posts one request to the forum-bff with the {@code @system} forum token
 * as the bearer, the same shape as {@link AkkomaSystemNoticeClient}.
 *
 * <h3>PROPOSED contract: nothing serves it yet</h3>
 * Neither {@code hugmesh-forum-bff-api} nor the {@code hugmesh-forum-api} phpBB extension
 * has a private-message route today (checked in their route tables when this was written:
 * the extension routes cover topics, replies, moderation, user ensure/groups and the
 * admin console, and forum-bff {@code /bff/forum/admin/**} has no send verb). The request
 * below is therefore a PROPOSAL that the fake server in the tests encodes; it was not run
 * against a real forum-bff or phpBB. Both peer repos need a matching endpoint before the
 * flag can deliver anything.
 *
 * <pre>
 * POST /bff/forum/system/private-messages
 * Authorization: Bearer &lt;@system forum token&gt;
 * Idempotency-Key: hm-&lt;outbox row id&gt;
 * {"recipient": "&lt;casdoor subject&gt;", "subject": "&lt;title&gt;", "text": "&lt;body&gt;"}
 * </pre>
 *
 * <h3>Outcome mapping (each line has a test)</h3>
 * <ul>
 *   <li>any 2xx: {@link ChannelOutcome#SENT} (by status alone; the reply body is not read).</li>
 *   <li>404 whose JSON body is {@code {"code":"unknown_recipient"}}: {@link ChannelOutcome#SKIPPED}.</li>
 *   <li>any other 404 (the route is absent, which is today's real state), 401, 4xx, 5xx and a
 *       transport error: {@link ChannelOutcome#FAILED} (retry). A missing route is therefore
 *       never a terminal skip.</li>
 *   <li>a blank recipient: {@link ChannelOutcome#SKIPPED} with no request; an absent token:
 *       {@link ChannelOutcome#FAILED} with no request.</li>
 * </ul>
 * Not covered by any test: a timeout, and a malformed reply body.
 *
 * <p>Ships dark: the bean exists only when {@code notify.forum.pm.wired=true}.
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns these singleton collaborators and they are never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class ForumSystemPmClient {

    private static final Logger log = LoggerFactory.getLogger(ForumSystemPmClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern KEY_UNSAFE = Pattern.compile("[^A-Za-z0-9_-]");

    /** The proposed forum-bff path (see the class javadoc). */
    static final String PATH = "/bff/forum/system/private-messages";
    /** The body code that tells "no such forum user" apart from "no such route". */
    static final String UNKNOWN_RECIPIENT = "unknown_recipient";

    private final WebClient http;
    private final SystemChannelTokens tokens;
    private final Duration timeout;

    public ForumSystemPmClient(WebClient http, SystemChannelTokens tokens, Duration timeout) {
        this.http = http;
        this.tokens = tokens;
        this.timeout = timeout;
    }

    private record Reply(int status, JsonNode body) {
        boolean ok() {
            return status >= 200 && status < 300;
        }

        boolean unknownRecipient() {
            return status == 404 && body != null && UNKNOWN_RECIPIENT.equals(body.path("code").asText());
        }
    }

    public Mono<ChannelOutcome> sendPrivateMessage(String recipientSubject, String title, String text,
                                                   String deliveryKey) {
        String recipient = recipientSubject == null ? "" : recipientSubject.trim();
        if (recipient.isEmpty()) {
            return Mono.just(ChannelOutcome.SKIPPED);
        }
        String token = tokens.forum().orElse(null);
        if (token == null) {
            return Mono.just(ChannelOutcome.FAILED);
        }
        String key = deliveryKey == null || deliveryKey.isBlank()
                ? UUID.randomUUID().toString()
                : "hm-" + KEY_UNSAFE.matcher(deliveryKey).replaceAll("_");
        return post(token, recipient, title, text, key)
                .map(r -> outcome(r, recipient))
                .onErrorResume(e -> {
                    log.warn("[notify-forum] PM to '{}' failed (retry next tick): {}", recipient, e.toString());
                    return Mono.just(ChannelOutcome.FAILED);
                })
                .defaultIfEmpty(ChannelOutcome.FAILED);
    }

    private static ChannelOutcome outcome(Reply r, String recipient) {
        if (r.ok()) {
            return ChannelOutcome.SENT;
        }
        if (r.unknownRecipient()) {
            log.debug("[notify-forum] '{}' has no forum account; SKIPPED", recipient);
            return ChannelOutcome.SKIPPED;
        }
        log.warn("[notify-forum] PM to '{}' HTTP {} (retry next tick)", recipient, r.status());
        return ChannelOutcome.FAILED;
    }

    private Mono<Reply> post(String token, String recipient, String title, String text, String key) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("recipient", recipient);
        body.put("subject", title == null ? "" : title);
        body.put("text", text == null ? "" : text);
        // Serialised here and sent as a String: the WebClient codecs are Jackson 3 and do
        // not encode a Jackson 2 tree (see MatrixSystemDmClient).
        return http.post().uri(PATH)
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

    private Mono<Reply> toReply(ClientResponse resp) {
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
}
