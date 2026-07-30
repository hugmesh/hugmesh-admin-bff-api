package systems.hugmesh.adminbff.suspension;

import java.time.Instant;

/**
 * A single {@code access_suspension} row — the desired-state record that drives the
 * single-writer reconcile loop (schema in Liquibase
 * {@code db/changelog/008-access-suspension.xml}).
 *
 * <p>The table is the SOLE source of truth: removing a Casdoor role on suspension
 * leaves no Casdoor record, so the loop computes
 * {@code desired_active = CasdoorMembers(role) MINUS active-suspensions} and drives
 * the homeserver active/suspended state + the Casdoor membership from these rows.
 *
 * <ul>
 *   <li>{@code role} — one of {@code ROLE_MATRIX}, {@code ROLE_MASTODON},
 *       {@code ROLE_MESH}, {@code PROFILE} (CHECK-constrained in the DB — 008 created
 *       the constraint, 330 widened it with {@code ROLE_MESH}; {@code @Pattern}-validated
 *       in {@link systems.hugmesh.adminbff.web.dto.SuspensionRequest}).</li>
 *   <li>{@code state} — {@code active} while the suspension is in force; the expiry
 *       action CASes it to {@code restored} at TTL (the row is never deleted — it is
 *       the audit trail).</li>
 *   <li>{@code expiresAt} — {@code null} means a PERMANENT ban; otherwise the single
 *       clock the expiry scan reads.</li>
 *   <li>{@code restoreRole} — whether the expiry action re-adds the Casdoor role (a
 *       permanent ban that should never auto-restore sets this false).</li>
 *   <li>{@code propagationState} — {@code pending}/{@code applied}/{@code failed},
 *       the homeserver-leg result the loop reconciles forward.</li>
 * </ul>
 */
public record AccessSuspension(
        String id,
        String casdoorUser,
        String localpart,
        String role,
        String state,
        Instant suspendedAt,
        Instant expiresAt,
        boolean restoreRole,
        String propagationState,
        String reason,
        String setBy,
        /** Tenant/brand discriminator, derived from the validated token issuer and
         *  stamped on write. {@code "default"} on single-issuer clusters. The admin
         *  read/write surface is scoped to this; the single-writer reconcile loop is
         *  cross-brand and ignores it. */
        String domain) {

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_RESTORED = "restored";

    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";

    public static final String ROLE_MATRIX = "ROLE_MATRIX";
    public static final String ROLE_MASTODON = "ROLE_MASTODON";
    /** The mesh access role (the gateway route-access floor for {@code /bff/mesh/**}).
     *  Unlike the two homeserver roles its suspension effect is the Casdoor
     *  role-membership drop ALONE — there is no mesh homeserver to deactivate; see
     *  {@link MeshAccessSyncAction} for why that single leg IS the ban. Added to the
     *  DB CHECK vocabulary by Liquibase changeset 330. */
    public static final String ROLE_MESH = "ROLE_MESH";
    public static final String ROLE_PROFILE = "PROFILE";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }

    /** A timed (non-permanent) suspension whose TTL has passed at {@code now}. */
    public boolean isExpiredAt(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }
}
