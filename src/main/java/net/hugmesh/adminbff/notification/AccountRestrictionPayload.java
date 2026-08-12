package net.hugmesh.adminbff.notification;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the {@code notification_outbox.payload} JSON for an account-restriction
 * (ban / timeout / unban) effect. This type is the single, CLOSED definition of what
 * the neutral {@code @system} sender is allowed to know about a restriction.
 *
 * <p><b>Identity rule (load-bearing).</b> The payload carries ONLY the fields below —
 * the {@code reason}, the {@code ttl} (seconds; null/absent = permanent), the affected
 * {@code role}, and a coarse {@code target} (the suspended principal, the message
 * recipient). It DELIBERATELY DOES NOT carry the acting mod/admin identity
 * ({@code set_by} / {@code mod_action.actor}): the {@code @system} sender is neutral
 * and must never expose who took the action. The builder takes no actor argument, so
 * the actor cannot leak even by accident — the same posture as the public
 * {@code AppealContact} resolver.
 */
public final class AccountRestrictionPayload {

    /** A single shared mapper — the payload shape is tiny + fixed. */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AccountRestrictionPayload() {
    }

    /**
     * Build the account-restriction payload JSON. NOTE: there is no actor parameter —
     * the acting mod/admin identity is intentionally absent.
     *
     * @param target     the affected principal (the notification recipient context)
     * @param role       the access role restricted (e.g. {@code PROFILE})
     * @param ttlSeconds the TTL in seconds, or {@code null} for a permanent restriction
     * @param reason     the moderation reason (may be null/blank)
     * @return a compact JSON object string (never contains the actor)
     */
    public static String build(String target, String role, Long ttlSeconds, String reason) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("target", target);
        body.put("role", role);
        // null ttl = permanent; surfaced as JSON null so the consumer can distinguish
        // "permanent" from "field absent".
        body.put("ttl_seconds", ttlSeconds);
        body.put("permanent", ttlSeconds == null);
        if (reason != null && !reason.isBlank()) {
            body.put("reason", reason);
        }
        try {
            return MAPPER.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            // The map holds only String/Long/Boolean — serialisation cannot realistically
            // fail; degrade to a minimal hand-rolled object rather than throwing out of a
            // ban transaction.
            return "{\"target\":" + quote(target) + ",\"role\":" + quote(role)
                    + ",\"permanent\":" + (ttlSeconds == null) + "}";
        }
    }

    private static String quote(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
