package systems.hugmesh.adminbff.device;

import java.time.Instant;
import java.util.List;

/**
 * A single {@code device_ssh_license} row — the explicit (operator x device|domain) SSH
 * grant (schema in Liquibase {@code db/changelog/011-device-license-registry.xml}). An
 * ACTIVE row means "this operator may SSH into this device (or every node resident in
 * this domain) PRESENTING one of the pinned keys". SUPERADMIN issues/revokes; the
 * registry compiles the active set into both enforcement layers off ONE signed export.
 *
 * <p>It is the audit trail: a revoke is a CAS {@code active -> revoked} (the row is NEVER
 * deleted), and every mutate bumps {@code generation} so the signed export's monotonic
 * rollback guard can reject a replayed (lower-generation) payload.
 *
 * <ul>
 *   <li>{@code scopeType} — {@code DEVICE} (one node, {@code deviceId} set) or
 *       {@code DOMAIN} (all nodes resident in {@code targetDomain}). The
 *       {@code chk_scope_shape} XOR ties exactly one target to the shape.</li>
 *   <li>{@code keyFingerprints} — FIX-PINKEY: the exact SSH pubkey fingerprint(s) the
 *       operator may present. The compiled export only emits a key whose offered
 *       {@code %f} matches one of these, so a licensed operator presenting an un-pinned
 *       key is still denied.</li>
 *   <li>{@code state} — {@code active} (grants SSH) / {@code revoked} (CAS, audited).</li>
 *   <li>{@code domain} — home/tenant discriminator for the ADMIN read view (defaults
 *       {@code 'default'}). A scoped admin reads only their brand's license rows.</li>
 *   <li>{@code propagationState} — FIX-REVOKE: the push-with-ack outcome
 *       ({@code pending}/{@code applied}/{@code failed}/{@code degraded}) the UI surfaces.</li>
 *   <li>{@code generation} — monotonic, bumped on every mutate; the export carries
 *       {@code max(generation)} so a node keeps its last-good cache and rejects a
 *       rolled-back payload (generation &le; current).</li>
 * </ul>
 */
public record SshLicense(
        String id,
        String operator,
        String scopeType,
        String deviceId,
        String targetDomain,
        String keyFingerprints,
        String state,
        String grantedBy,
        Instant grantedAt,
        Instant revokedAt,
        String revokedBy,
        String domain,
        String propagationState,
        long generation) {

    public static final String SCOPE_DEVICE = "DEVICE";
    public static final String SCOPE_DOMAIN = "DOMAIN";

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_REVOKED = "revoked";

    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";
    public static final String PROP_DEGRADED = "degraded";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }

    public boolean isDeviceScoped() {
        return SCOPE_DEVICE.equals(scopeType);
    }

    public boolean isDomainScoped() {
        return SCOPE_DOMAIN.equals(scopeType);
    }

    /**
     * The pinned fingerprints parsed into a normalised list (comma / whitespace /
     * newline separated, blanks dropped). FIX-PINKEY: the export matches an offered
     * {@code %f} against this set. An empty set means the license pins NO key — the
     * compiler emits nothing for it (fail-closed).
     */
    public List<String> fingerprints() {
        if (keyFingerprints == null || keyFingerprints.isBlank()) return List.of();
        String[] parts = keyFingerprints.trim().split("[,\\s]+");
        List<String> out = new java.util.ArrayList<>(parts.length);
        for (String p : parts) {
            String t = p.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }
}
