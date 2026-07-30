package systems.hugmesh.adminbff.notification;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the {@code notification_outbox.payload} JSON for a backup/restore infra event
 * ({@code backup-started} / {@code restore-started}). This type is the single, CLOSED
 * definition of what the neutral {@code @system} sender is allowed to know about a
 * backup/restore run.
 *
 * <p><b>Identity rule (load-bearing).</b> The payload carries ONLY the coarse run
 * context below — the {@code scope} ({@code domain}/{@code total}), the {@code version},
 * a {@code services} COUNT (never the service names — those can hint at the brand's
 * topology), and the {@code destination_kind} (a coarse kind, never the bucket/pool ref
 * or any credential). It DELIBERATELY DOES NOT carry the acting admin/superadmin identity
 * ({@code created_by} / {@code requested_by}): the {@code @system} sender is neutral and
 * must never expose who took the action. It also never carries the encryption meta /
 * destination ref / any key or credential reference. The builder takes no actor argument,
 * so the actor cannot leak even by accident — the same posture as
 * {@link AccountRestrictionPayload}.
 */
public final class BackupNotificationPayload {

    /** A single shared mapper — the payload shape is tiny + fixed. */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private BackupNotificationPayload() {
    }

    /**
     * Build the backup/restore payload JSON. NOTE: there is no actor parameter — the
     * acting admin/superadmin identity is intentionally absent, as is the destination
     * ref / encryption meta / any credential.
     *
     * @param scope           the backup scope ({@code domain} or {@code total})
     * @param version         the allocated set version (the version-chain run number)
     * @param serviceCount    how many services were selected (COUNT only, never names)
     * @param destinationKind the coarse destination KIND (e.g. {@code object_store}),
     *                        or {@code null} for a restore (no fresh destination chosen)
     * @return a compact JSON object string (never contains the actor or any credential)
     */
    public static String build(String scope, long version, int serviceCount, String destinationKind) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("scope", scope);
        body.put("version", version);
        body.put("service_count", serviceCount);
        if (destinationKind != null && !destinationKind.isBlank()) {
            body.put("destination_kind", destinationKind);
        }
        try {
            return MAPPER.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            // The map holds only String/Long/Integer — serialisation cannot realistically
            // fail; degrade to a minimal hand-rolled object rather than throwing out of a
            // backup transaction.
            return "{\"scope\":" + quote(scope) + ",\"version\":" + version
                    + ",\"service_count\":" + serviceCount + "}";
        }
    }

    private static String quote(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
