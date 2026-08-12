package net.hugmesh.adminbff.desktop;

import java.time.Instant;

/**
 * A single {@code desktop_app_catalog} row — one app ref in a brand's Plasma Discover
 * allowlist (schema in Liquibase {@code db/changelog/140-desktop-app-governance.xml}).
 *
 * <p>The store is <b>DEFAULT-NONE</b>: {@link #enabled} is DEFAULT FALSE, so adding a ref
 * to the catalog does NOT make it appear in Discover. The discover-role registry endpoint
 * ({@link DesktopRegistryController}) serves ONLY this domain's <b>enabled</b> refs; an
 * empty catalog (or a catalog with everything disabled) serves NOTHING. A ref not in the
 * enabled allowlist is denied (404), with no cross-domain leak — the catalog is per-domain
 * (UNIQUE per {@code domain + app_ref}, {@code domain} stamped from the validated issuer).
 *
 * <ul>
 *   <li>{@code appRef} — the Flatpak/OCI app reference (e.g. {@code org.mozilla.firefox}).</li>
 *   <li>{@code source} — {@code FLATPAK} (over the OCI registry) or {@code OCI}.</li>
 *   <li>{@code enabled} — false by default; the store is default-NONE.</li>
 *   <li>{@code domain} — the brand the entry belongs to (validated issuer; the read scope
 *       predicate).</li>
 * </ul>
 */
public record DesktopAppCatalogEntry(
        String id,
        String appRef,
        String displayName,
        String source,
        boolean enabled,
        String addedBy,
        String domain,
        Instant createdAt,
        Instant updatedAt) {

    public static final String SOURCE_FLATPAK = "FLATPAK";
    public static final String SOURCE_OCI = "OCI";
}
