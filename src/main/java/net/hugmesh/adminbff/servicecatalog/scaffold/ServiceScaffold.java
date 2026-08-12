package net.hugmesh.adminbff.servicecatalog.scaffold;

import java.time.Instant;

/**
 * A single {@code service_scaffold} row — the per-domain record of a SCAFFOLD a SUPERADMIN
 * requested from the Service-Store wizard (schema in Liquibase
 * {@code db/changelog/320-service-scaffold.xml}). It records WHICH example {@link #archetype()}
 * was picked for a brand/domain, the intended {@link #mountAt()} + {@link #requiresRole()}
 * federation hints, and the lifecycle {@link #state()}.
 *
 * <p>Desired-state, never hard-deleted (the 100/102 App-Store convention):
 * <ul>
 *   <li>{@link #state()} — {@code requested} when created; the archive endpoint CASes it to
 *       {@code archived} when the starter codebase is first materialised (the row is kept as
 *       the audit trail, like the curation/deployment rows).</li>
 *   <li>{@link #domain()} — the per-row tenant discriminator (the 010 pattern); the superadmin
 *       create/archive surface targets an EXPLICIT domain (never a body field).</li>
 * </ul>
 * The scaffold is DATA/INTENT only — nothing is deployed. The rendered ZIP is produced on demand
 * from the embedded skeleton; federating the resulting service is the separate federate leg.
 */
public record ServiceScaffold(
        String id,
        /** Tenant/brand discriminator (the 010 pattern); the superadmin surface targets it. */
        String domain,
        String serviceKey,
        /** The chosen {@link ScaffoldArchetype#name()} (a catalog member). */
        String archetype,
        /** Nullable human label (defaults to {@code serviceKey} when rendering). */
        String displayName,
        /** Nullable intended federation mount path (e.g. {@code /owncast}). */
        String mountAt,
        /** Nullable intended {@code requiresRole} federation gate. */
        String requiresRole,
        String state,
        /** The SUPERADMIN subject ({@code jwt.getSubject()}) who requested the scaffold. */
        String createdBySubject,
        Instant createdAt,
        Instant updatedAt) {

    public static final String STATE_REQUESTED = "requested";
    public static final String STATE_ARCHIVED = "archived";
}
