package systems.hugmesh.adminbff.workload;

import java.time.Instant;

/**
 * A WORKLOAD CONSOLE grant LEASE — the row a SUPERADMIN issues so a brand ADMIN may
 * read-only-view their OWN-domain app-tier workloads. CLONES {@code device_ssh_license}
 * (011) verbatim: app-generated varchar(36) UUID PK, CAS {@code active}-&gt;
 * {@code revoked}/{@code expired} (never deleted = audit), monotonic {@link #generation},
 * {@link #propagationState}, {@link #domain} stamped from the validated issuer.
 *
 * <p>NEW vs 011 (DECISION 4):
 * <ul>
 *   <li>{@link #accessLevel} is CHECK-pinned to {@link #ACCESS_READ_ONLY} — an admin grant
 *       can NEVER be more than read-only;</li>
 *   <li>{@link #logAccess} defaults FALSE — log BODIES are UN-bundled from the
 *       status/topology/metrics read (a separate opt-in);</li>
 *   <li>{@link #expiresAt} is NOT NULL — every grant is a ~24h TTL LEASE; a scheduled sweep
 *       CASes {@code active}-&gt;{@code expired}, returning the admin to dark automatically.</li>
 * </ul>
 */
public record WorkloadConsoleGrant(
        String id,
        String grantee,
        String targetDomain,
        String accessLevel,
        boolean logAccess,
        String state,
        String grantedBy,
        Instant grantedAt,
        Instant expiresAt,
        Instant revokedAt,
        String revokedBy,
        String domain,
        String propagationState,
        long generation) {

    public static final String ACCESS_READ_ONLY = "READ_ONLY";

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_REVOKED = "revoked";
    public static final String STATE_EXPIRED = "expired";

    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";
    public static final String PROP_DEGRADED = "degraded";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }

    /** A grant is honoured only while active AND not past its TTL. */
    public boolean isLiveAt(Instant now) {
        return isActive() && expiresAt != null && expiresAt.isAfter(now);
    }
}
