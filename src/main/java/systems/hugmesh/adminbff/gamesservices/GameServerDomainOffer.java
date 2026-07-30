package systems.hugmesh.adminbff.gamesservices;

import java.time.Instant;

/**
 * A single {@code game_server_domain_offer} row — the per-({@code domain}, catalog
 * {@code slug}) TWO-TIER offer that the games app-store uses to gate which domains may
 * run which catalog servers (schema in Liquibase
 * {@code db/changelog/090-games-server-catalog.xml}).
 *
 * <p>Modelled on the announcement per-domain pattern (a {@code domain} tenant
 * discriminator + the offered slug). Two tiers + the creation gate:
 * <ul>
 *   <li>{@link #offeredBySuperadmin()} — TIER 1, the SUPERADMIN creation gate. A
 *       superadmin must OFFER a catalog slug to a domain before that domain's admin can
 *       enable/run it. Fail-closed: no offer row (or {@code false}) = the domain cannot
 *       use the server.</li>
 *   <li>{@link #enabledByAdmin()} — TIER 2, the domain admin's own per-domain on/off.</li>
 *   <li>{@link #maxInstances()} — the per-(domain, slug) instance quota the creation gate
 *       (PR6) enforces; {@code 0} = offered but no instances permitted.</li>
 * </ul>
 *
 * <p>The EFFECTIVE availability of a server to a domain is
 * {@code catalog.enabled AND offeredBySuperadmin AND enabledByAdmin}, computed in the
 * service (not the DB).
 */
public record GameServerDomainOffer(
        String id,
        String domain,
        String slug,
        boolean offeredBySuperadmin,
        boolean enabledByAdmin,
        int maxInstances,
        Instant createdAt,
        String createdBySubject,
        Instant updatedAt) {
}
