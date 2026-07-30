package systems.hugmesh.adminbff.servicecatalog;

import java.time.Instant;

/**
 * A single {@code service_curation} row — the per-domain TWO-TIER offered-catalog
 * record for the Superadmin App-Store (schema in Liquibase
 * {@code db/changelog/100-service-curation.xml}).
 *
 * <p>It records, per brand/{@link #domain()}, the set of {@code service_key}s a
 * SUPERADMIN has OFFERED to that domain's admins. The two tiers:
 * <ul>
 *   <li>SUPERADMIN (the cross-domain infra control plane) WRITES the table — offers /
 *       withdraws a service_key FOR a specific {@code domain} (it targets any brand;
 *       it is unscoped).</li>
 *   <li>a brand ADMIN READS only the rows for THEIR OWN issuer-derived domain (the
 *       {@code /bff/admin/service-store} surface): an admin sees ONLY services the
 *       superadmin offered to THEIR domain, never another domain's catalog.</li>
 * </ul>
 *
 * <p>Desired-state, never-hard-delete (the {@code access_suspension} convention):
 * {@link #state()} is {@code offered} while a service is live in the catalog, and a
 * withdrawal CASes it to {@code withdrawn} (the row stays as the audit trail). A partial
 * UNIQUE {@code (domain, service_key) WHERE state='offered'} guarantees at most ONE live
 * offer per (domain, service).
 */
public record ServiceCuration(
        String id,
        /** Tenant/brand discriminator (the 010 pattern), the brand the superadmin offered
         *  this service TO. The admin read surface is scoped to this; the superadmin write
         *  surface targets a specific value. */
        String domain,
        String serviceKey,
        String state,
        /** The SUPERADMIN subject ({@code jwt.getSubject()}) who offered/withdrew. */
        String curatedBySubject,
        Instant createdAt,
        Instant updatedAt) {

    public static final String STATE_OFFERED = "offered";
    public static final String STATE_WITHDRAWN = "withdrawn";

    public boolean isOffered() {
        return STATE_OFFERED.equals(state);
    }
}
