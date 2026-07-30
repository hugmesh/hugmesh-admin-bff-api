package systems.hugmesh.adminbff.web.dto;

import systems.hugmesh.adminbff.gamesservices.GameServerDomainOffer;

import java.time.Instant;

/**
 * Response view of a {@code game_server_domain_offer} row (schema 090) — a straight
 * projection of {@link GameServerDomainOffer}.
 */
public record GameDomainOfferResponse(
        String id,
        String domain,
        String slug,
        boolean offeredBySuperadmin,
        boolean enabledByAdmin,
        int maxInstances,
        Instant createdAt,
        String createdBySubject,
        Instant updatedAt) {

    public static GameDomainOfferResponse of(GameServerDomainOffer o) {
        return new GameDomainOfferResponse(o.id(), o.domain(), o.slug(),
                o.offeredBySuperadmin(), o.enabledByAdmin(), o.maxInstances(),
                o.createdAt(), o.createdBySubject(), o.updatedAt());
    }
}
