package net.hugmesh.adminbff.web.dto;

import net.hugmesh.adminbff.gamesservices.GameServerCatalogEntry;

import java.time.Instant;

/**
 * Response view of a {@code game_server_catalog} row (schema 090) — a straight projection
 * of {@link GameServerCatalogEntry} (no secrets; {@code imageRef} is a digest-pinned public
 * reference).
 */
public record GameCatalogEntryResponse(
        String id,
        String slug,
        String displayName,
        String imageRef,
        String licenseSpdx,
        String protocol,
        int containerPort,
        Integer consolePort,
        String summary,
        boolean enabled,
        Instant createdAt,
        String createdBySubject,
        Instant updatedAt) {

    public static GameCatalogEntryResponse of(GameServerCatalogEntry e) {
        return new GameCatalogEntryResponse(e.id(), e.slug(), e.displayName(), e.imageRef(),
                e.licenseSpdx(), e.protocol(), e.containerPort(), e.consolePort(), e.summary(),
                e.enabled(), e.createdAt(), e.createdBySubject(), e.updatedAt());
    }
}
