package net.hugmesh.adminbff.web.dto;

import net.hugmesh.adminbff.gamesservices.GameInstance;
import net.hugmesh.adminbff.gamesservices.GameServerCatalogEntry;

/**
 * Connection info for a running game instance — how a player reaches it. Returned by
 * {@code GET /bff/games-services/instances/{id}/connection}.
 *
 * <ul>
 *   <li>{@code protocol} — the L4 game protocol ({@code tcp}/{@code udp}/{@code both}) or
 *       {@code none} for an HTTP-console-only server.</li>
 *   <li>{@code nodePort} — the reserved-pool NodePort the raw game protocol is exposed on
 *       (null / -1 when the server is HTTP-console-only). The player connects to
 *       {@code <node-host>:<nodePort>} over the tailnet.</li>
 *   <li>{@code consolePath} — the be-gateway path the HTTP console is routed at
 *       ({@code /games/servers/<slug>/<name>/}), or null.</li>
 *   <li>{@code state} — the instance lifecycle state (only {@code active} is reachable).</li>
 * </ul>
 *
 * <p>No host/IP is returned here: the node host is tailnet-resolved by the client (the BFF
 * does not leak node addressing). RCON/admin ports are tailnet-only ClusterIP and are never
 * surfaced.
 */
public record GameInstanceConnectionResponse(
        String id,
        String slug,
        String name,
        String state,
        String protocol,
        Integer nodePort,
        String consolePath) {

    public static GameInstanceConnectionResponse of(GameInstance i, GameServerCatalogEntry entry) {
        String protocol = entry == null ? null : entry.protocol();
        // A -1 sentinel (HTTP-only console marker) is surfaced as no NodePort.
        Integer port = (i.nodePort() == null || i.nodePort() < 0) ? null : i.nodePort();
        return new GameInstanceConnectionResponse(i.id(), i.slug(), i.name(), i.state(),
                protocol, port, i.consolePath());
    }
}
