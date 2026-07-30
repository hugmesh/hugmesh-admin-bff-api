package systems.hugmesh.adminbff.golive;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One GO-LIVE INTENT — a superadmin's recorded request to take a brand public
 * ({@code targetState="public"}) or roll it back internal ({@code targetState="internal"}).
 * The durable shape of a {@code go_live_intent} row (Liquibase 270).
 *
 * <p><b>INTENT, not effect.</b> The go-live switch is the HOST file
 * {@code /etc/hugmesh/go-live} (+ {@code /etc/hugmesh/release-state}), converged by the
 * host-side {@code hugmesh-firewall-reconcile} — an in-cluster BFF can never write it and,
 * per the pinned contract, must never pretend it did. {@code status} is therefore
 * {@code recorded} / {@code withdrawn} from the BFF; ONLY the host-side go-live agent (after
 * verifying the signed export) may ack {@code applied} + stamp {@code appliedAt}/{@code
 * appliedBy}.
 *
 * <p>NO SECRETS: {@code provider} is a {@link GoLiveProviderCatalog} key — tunnel/DNS/DDNS
 * tokens never ride this record (they route to keys-USB/Vault on the generator side).
 */
public record GoLiveIntent(
        String id,
        String clusterDomain,
        String targetState,
        String exposureModel,
        String provider,
        String status,
        String note,
        String requestedBySubject,
        Instant createdAt,
        Instant updatedAt,
        long generation,
        Instant appliedAt,
        String appliedBy) {

    /** BFF write states. */
    public static final String STATUS_RECORDED = "recorded";
    public static final String STATUS_WITHDRAWN = "withdrawn";
    /** HOST-AGENT ack state — the BFF NEVER writes this (contract: intent only). */
    public static final String STATUS_APPLIED = "applied";

    /** Host RELEASE_STATE vocabulary. */
    public static final String TARGET_PUBLIC = "public";
    public static final String TARGET_INTERNAL = "internal";

    /** The wire map the wizard UI renders — makes the intent-only contract EXPLICIT:
     *  {@code applied} is true ONLY once the host agent has acked, never on record. */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("clusterDomain", clusterDomain);
        m.put("targetState", targetState);
        m.put("exposureModel", exposureModel);
        m.put("provider", provider);
        m.put("status", status);
        m.put("note", note);
        m.put("requestedBySubject", requestedBySubject);
        m.put("createdAt", createdAt);
        m.put("updatedAt", updatedAt);
        m.put("generation", generation);
        m.put("applied", STATUS_APPLIED.equals(status));
        m.put("appliedAt", appliedAt);
        m.put("appliedBy", appliedBy);
        return m;
    }
}
