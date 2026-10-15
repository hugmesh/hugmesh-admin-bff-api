package net.hugmesh.adminbff.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The moderator's per-action channel directive (mod-bff's {@code notifyChannels}), as it
 * travels on the {@code notification_outbox.payload} under {@link #KEY}.
 *
 * <h3>Vocabulary and unknown names</h3>
 * mod-bff names channels {@code in-app}, {@code email}, {@code matrix} and
 * {@code mastodon}; this service's external channels are {@code matrix}, {@code email},
 * {@code akkoma} and {@code forum}. {@link #normalize} maps onto the closed set below
 * ({@code mastodon} is the Mastodon-API platform, so it maps to the {@code akkoma}
 * channel). A well-formed name outside that set is IGNORED with a warning, never
 * rejected: a directive from a newer mod-bff must not fail a ban. (A malformed token
 * is a 400 at the request boundary, see {@code SuspensionRequest}.)
 *
 * <h3>What the directive can and cannot do</h3>
 * It only ever NARROWS the external fan-out of the rows it is stamped on:
 * <ul>
 *   <li>It never enables anything. A channel the directive names that is disabled or
 *       unavailable stays disabled or unavailable: the reconciler's
 *       {@code enabled()}/{@code available()} gates are applied exactly as before.</li>
 *   <li>{@code in-app} is the only guaranteed floor and is not an external channel: the
 *       in-app reconciler never reads the directive, so a restriction always reaches the
 *       user's own console whatever the directive says. No external delivery is
 *       guaranteed.</li>
 *   <li>A directive that names no ENABLED external channel (absent, empty, {@code in-app}
 *       only, only unknown names, or only disabled channels) is treated as absent and the
 *       default fan-out applies. This also means a moderator's "email only" choice with
 *       email disabled widens to the full default fan-out (matrix, akkoma, forum) rather
 *       than narrowing it.</li>
 *   <li>A directive that DOES name an enabled channel is not checked against that
 *       channel's {@code available()} or recipient resolution. If every named channel is
 *       unavailable (a stub transport, no SMTP, an unwired seam) or skips the row (email
 *       with no resolvable address), the excluded channels have already recorded a
 *       terminal {@code skipped}, so NO external channel delivers that row, and the skip is
 *       never retried when the named channel later recovers. Only in-app is certain.</li>
 * </ul>
 */
public final class NotifyChannelDirective {

    /** The outbox payload key. */
    public static final String KEY = "notify_channels";
    /** The in-app floor name (never an external channel). */
    public static final String IN_APP = "in-app";

    private static final Logger log = LoggerFactory.getLogger(NotifyChannelDirective.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Accepted request name to canonical channel name. */
    private static final Map<String, String> CANONICAL = Map.of(
            "in-app", IN_APP,
            "email", "email",
            "matrix", "matrix",
            "akkoma", "akkoma",
            "mastodon", "akkoma",
            "forum", "forum");

    private NotifyChannelDirective() {
    }

    /**
     * Canonicalise a raw request list: trimmed, lower-cased, {@code mastodon} mapped to
     * {@code akkoma}, de-duplicated, order-stable; blank and unknown names dropped (unknown
     * ones with a warning). Never null; empty means "no directive". (Over HTTP the request
     * pattern already rejects capitals and spaces with a 400, so trimming and lower-casing
     * only matter to direct callers of this method.)
     */
    public static List<String> normalize(List<String> raw) {
        if (raw == null || raw.isEmpty()) {
            return List.of();
        }
        Set<String> out = new LinkedHashSet<>();
        for (String name : raw) {
            if (name == null || name.isBlank()) {
                continue;
            }
            String canonical = CANONICAL.get(name.trim().toLowerCase(Locale.ROOT));
            if (canonical == null) {
                log.warn("[notify-directive] ignoring unknown notify channel '{}'", sanitize(name));
            } else {
                out.add(canonical);
            }
        }
        return List.copyOf(out);
    }

    /**
     * May {@code channelName} deliver the row whose payload is {@code payload}? Applied
     * BEFORE the channel's own availability gate; a false answer is a terminal skip.
     *
     * @param enabledChannelNames the names of the external channels whose enabled() gate is on
     */
    public static boolean allows(String payload, String channelName, Collection<String> enabledChannelNames) {
        Set<String> narrowed = narrowedTo(payload, enabledChannelNames);
        return narrowed.isEmpty() || narrowed.contains(channelName);
    }

    /** The external channels the payload narrows to, or empty when it does not narrow. */
    static Set<String> narrowedTo(String payload, Collection<String> enabledChannelNames) {
        Set<String> named = new LinkedHashSet<>();
        for (String n : read(payload)) {
            String canonical = CANONICAL.get(n.trim().toLowerCase(Locale.ROOT));
            // in-app is never in enabledChannelNames (those are external channels), so it cannot narrow.
            if (canonical != null && enabledChannelNames.contains(canonical)) {
                named.add(canonical);
            }
        }
        return named;
    }

    private static List<String> read(String payload) {
        if (payload == null || payload.isBlank()) {
            return List.of();
        }
        try {
            JsonNode arr = MAPPER.readTree(payload).get(KEY);
            if (arr == null || !arr.isArray()) {
                return List.of();
            }
            List<String> out = new java.util.ArrayList<>();
            arr.forEach(e -> {
                if (e.isTextual()) {
                    out.add(e.asText());
                }
            });
            return out;
        } catch (Exception e) {
            return List.of();
        }
    }

    /** Keep an attacker-chosen token from forging log lines. */
    static String sanitize(String s) {
        String t = s.length() > 64 ? s.substring(0, 64) : s;
        return t.replaceAll("[^A-Za-z0-9 _.:/-]", "?");
    }
}
