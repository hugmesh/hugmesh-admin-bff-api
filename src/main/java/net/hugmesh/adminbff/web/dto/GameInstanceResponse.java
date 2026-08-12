package net.hugmesh.adminbff.web.dto;

import net.hugmesh.adminbff.gamesservices.GameInstance;

import java.time.Instant;

/**
 * Response view of a {@code game_instance} row (schema 091) — a straight projection of
 * {@link GameInstance}. {@code nodePort}/{@code consolePath} are allocated by the port
 * exposure PR (PR7) and may be null until then.
 */
public record GameInstanceResponse(
        String id,
        String domain,
        String slug,
        String name,
        String state,
        String propagationState,
        String ownerSubject,
        Instant createdAt,
        Instant endingAt,
        String namespace,
        Integer nodePort,
        String consolePath,
        Instant updatedAt) {

    public static GameInstanceResponse of(GameInstance i) {
        return new GameInstanceResponse(i.id(), i.domain(), i.slug(), i.name(), i.state(),
                i.propagationState(), i.ownerSubject(), i.createdAt(), i.endingAt(),
                i.namespace(), i.nodePort(), i.consolePath(), i.updatedAt());
    }
}
