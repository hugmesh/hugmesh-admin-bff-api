package systems.hugmesh.adminbff.servicecatalog;

import java.time.Instant;

/**
 * A single {@code service_deployment} row — the per-domain LIFECYCLE-ACCOUNTING record
 * for the App-Store (schema in Liquibase {@code db/changelog/102-service-deployment.xml}).
 *
 * <p>This record CLONES the {@code access_suspension} (008) desired-state shape +
 * conventions:
 * <ul>
 *   <li>{@link #state()} — {@code active} while the deployment is in force; the expiry
 *       action CASes it to {@code ended} at {@link #endingAt()} (the row is NEVER
 *       hard-deleted — it is the audit trail), the {@code active -> restored} twin.</li>
 *   <li>{@link #endingAt()} — the SINGLE expiry clock (the {@code expires_at} twin):
 *       {@code null} = no-expiry (a permanent deployment); a non-null value is the instant
 *       the lease-gated single-writer tick flips {@code active -> ended}.</li>
 *   <li>{@link #propagationState()} — {@code pending}/{@code applied}/{@code failed}, the
 *       enforce-actions leg result the loop self-heals forward.</li>
 *   <li>{@link #domain()} — the per-row tenant discriminator (the 010 pattern), so a brand
 *       ADMIN only sees their own brand's deployments and a SUPERADMIN targets a specific
 *       brand.</li>
 * </ul>
 *
 * <p>{@link #enforceActions()} is an opaque JSON/CSV list of the effects to EMIT at
 * end-of-lease (e.g. {@code teardown,revoke-roles,revoke-certs,alert}); in PR1 these are
 * STUBBED/LOGGED (ships dark — no real ArgoCD/Casdoor/cert call). {@link #profileRef()} is
 * a NULLABLE soft reference to an {@link AppProfile#name()} — the template the deployment
 * was stamped from. {@link #endedAt()} is stamped when the row CASes {@code active->ended}.
 */
public record ServiceDeployment(
        String id,
        /** Tenant/brand discriminator (the 010 pattern). The admin read surface is scoped
         *  to this; the superadmin create/list surface targets a specific value. */
        String domain,
        String serviceKey,
        String profileRef,
        String state,
        Instant createdAt,
        /** The SINGLE expiry clock. {@code null} = no-expiry (permanent deployment). */
        Instant endingAt,
        /** Opaque JSON/CSV of the enforce effects EMITTED at end-of-lease (SHIPS DARK). */
        String enforceActions,
        String propagationState,
        /** Stamped when the row CASes {@code active->ended}. */
        Instant endedAt,
        /** The SUPERADMIN subject ({@code jwt.getSubject()}) who created the deployment. */
        String createdBySubject) {

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_ENDED = "ended";

    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }

    /** A deployment with an expiry clock whose instant has passed at {@code now}. */
    public boolean isEndingDueAt(Instant now) {
        return endingAt != null && !endingAt.isAfter(now);
    }
}
