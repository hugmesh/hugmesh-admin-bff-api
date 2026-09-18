package net.hugmesh.adminbff.servicecatalog;

import java.time.Instant;

/**
 * A single {@code app_profile} row — a reusable, SUPERADMIN-owned deploy TEMPLATE for the
 * App-Store (schema in Liquibase {@code db/changelog/101-app-profile.xml}).
 *
 * <p>A profile is a named bundle of resource/role/cert/exposure DEFAULTS (carried as a JSON
 * document in {@link #profileJson()}) a {@link ServiceDeployment} can reference, so a superadmin
 * curates a small set of templates and stamps them onto many deployments.
 *
 * <p><b>GLOBAL, not per-domain.</b> Unlike {@link ServiceCuration} and
 * {@link ServiceDeployment}, app_profile carries NO per-row tenant discriminator: the
 * templates are a shared, superadmin-owned library reused ACROSS brands. It is therefore
 * inherently CROSS-DOMAIN and only ever read/written by the cross-domain SUPERADMIN role.
 * {@link #name()} is the UNIQUE natural key. {@link #profileJson()} is stored verbatim and is
 * still not RESOLVED by anything (that is the effector, open on catalog-ui#3) — but since issue
 * #55 it is no longer stored unchecked: {@link AppProfileService} validates it against
 * {@link AppProfileSchema} before every write. Reads are never validated and never rewritten, so
 * a row written before the schema existed stays readable and fixable in the console.
 */
public record AppProfile(
        String id,
        String name,
        String profileJson,
        /** The SUPERADMIN subject ({@code jwt.getSubject()}) who created the template. */
        String createdBySubject,
        Instant createdAt,
        Instant updatedAt) {
}
