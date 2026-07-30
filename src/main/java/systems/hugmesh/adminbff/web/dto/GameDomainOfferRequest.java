package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST/PUT /bff/superadmin/games-services/offers/{domain}[/{slug}]}
 * (SUPERADMIN) — offer a catalog server to a domain or update an existing offer
 * (schema 090). The {@code domain} (and on update, {@code slug}) come from the PATH.
 *
 * <ul>
 *   <li>{@code slug} — the catalog entry being offered (required on create; the entry
 *       must already exist).</li>
 *   <li>{@code offeredBySuperadmin} — the TIER-1 creation gate. Defaults true on create
 *       (offering it IS the gate flip); set false to WITHDRAW an offer.</li>
 *   <li>{@code enabledByAdmin} — usually left to the domain admin (PR6); the superadmin
 *       may pre-set it.</li>
 *   <li>{@code maxInstances} — the per-(domain,slug) quota; defaults 1 on create. {@code 0}
 *       = offered but no instances permitted.</li>
 * </ul>
 */
public record GameDomainOfferRequest(
        @Size(max = 64, message = "slug is too long")
        @Nullable
        String slug,

        @Nullable
        Boolean offeredBySuperadmin,

        @Nullable
        Boolean enabledByAdmin,

        @Nullable
        Integer maxInstances) {
}
