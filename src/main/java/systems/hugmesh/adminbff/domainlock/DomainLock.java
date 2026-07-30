package systems.hugmesh.adminbff.domainlock;

import java.time.Instant;

/**
 * A single {@code domain_lock} row — the desired-state record that drives the
 * single-writer DOMAIN-LOCK reconcile loop (schema in Liquibase
 * {@code db/changelog/009-domain-lock.xml}).
 *
 * <p>This is the ADD-semantics sibling of
 * {@link systems.hugmesh.adminbff.suspension.AccessSuspension} (and a
 * DELIBERATELY SEPARATE table): an ACTIVE row means "ADD/KEEP the
 * {@code ROLE_*_DOMAINLOCKED} marker on this user" (force local-only / no-federation),
 * whereas an active access_suspension row means "DROP the role". The locked user
 * RETAINS their {@code ROLE_MATRIX}/{@code ROLE_MASTODON} — the gateway is untouched;
 * the marker is purely additive and the homeserver/egress force-local effect is what
 * actually enforces non-federation.
 *
 * <p>The set of ACTIVE rows IS the force-local allowlist the generator akkoma MRF /
 * egress proxy reads ({@link DomainLockRepository#activeByRole}): active rows for
 * {@code ROLE_MASTODON_DOMAINLOCKED} materialize the Mastodon force-local set,
 * {@code ROLE_MATRIX_DOMAINLOCKED} the Matrix one. There is no separate allowlist
 * table — domain_lock IS the source.
 *
 * <ul>
 *   <li>{@code role} — one of {@code ROLE_MATRIX_DOMAINLOCKED},
 *       {@code ROLE_MASTODON_DOMAINLOCKED} (CHECK-constrained in the DB;
 *       {@code @Pattern}-validated in
 *       {@link systems.hugmesh.adminbff.web.dto.DomainLockRequest}).</li>
 *   <li>{@code state} — {@code active} while the lock is in force (enforce); the loop
 *       CASes it to {@code removed} on unlock (the row is never deleted — it is the
 *       audit trail).</li>
 *   <li>{@code propagationState} — {@code pending}/{@code applied}/{@code failed}/
 *       {@code degraded}, the homeserver/egress force-local-leg result the loop
 *       reconciles forward.</li>
 * </ul>
 */
public record DomainLock(
        String id,
        String casdoorUser,
        String localpart,
        String role,
        String state,
        Instant createdAt,
        String propagationState,
        String reason,
        String setBy,
        /** Tenant/brand discriminator, derived from the validated token issuer and
         *  stamped on write. {@code "default"} on single-issuer clusters. The admin
         *  read/write surface is scoped to this; the single-writer reconcile loop +
         *  the force-local materialization are cross-brand and ignore it. */
        String domain) {

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_REMOVED = "removed";

    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";
    public static final String PROP_DEGRADED = "degraded";

    /** ADDITIVE force-local marker: the user KEEPS ROLE_MATRIX, but is no-federation. */
    public static final String ROLE_MATRIX_DOMAINLOCKED = "ROLE_MATRIX_DOMAINLOCKED";
    /** ADDITIVE force-local marker: the user KEEPS ROLE_MASTODON, but is no-federation. */
    public static final String ROLE_MASTODON_DOMAINLOCKED = "ROLE_MASTODON_DOMAINLOCKED";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }
}
