package net.hugmesh.adminbff.gamesservices;

import java.time.Instant;

/**
 * A single {@code game_server_catalog} row — one FOSS dockerized game server in the
 * GLOBAL, SUPERADMIN-curated games app-store catalog (schema in Liquibase
 * {@code db/changelog/090-games-server-catalog.xml}).
 *
 * <p>Modelled on {@link net.hugmesh.adminbff.domainregistry.DomainRegistration}:
 * the catalog is inherently CROSS-DOMAIN (only the cross-domain SUPERADMIN curates it),
 * so this carries NO per-row tenant {@code domain} discriminator. {@code slug} is the
 * UNIQUE natural key; a server is SOFT-DISABLED ({@code enabled=false}), never
 * hard-deleted (live per-domain offers reference it).
 *
 * <p><b>Digest-pin invariant.</b> {@code imageRef} MUST be a digest-pinned reference
 * ({@code repo@sha256:<64hex>}). A tag-only reference is rejected by
 * {@link ImageRef#validate(String)} (the primary, server-side gate) AND by a DB CHECK
 * ({@code image_ref LIKE '%@sha256:%'}). Arbitrary-container exec is the core risk of an
 * app-store of game servers, so a mutable tag (re-pointable at a malicious image after
 * curation) is never accepted.
 */
public record GameServerCatalogEntry(
        String id,
        String slug,
        String displayName,
        String imageRef,
        /** SPDX license identifier of the upstream FOSS server (e.g. {@code GPL-3.0-or-later}). */
        String licenseSpdx,
        /** L4 game protocol the raw port speaks: {@code tcp}/{@code udp}/{@code both}/{@code none}. */
        String protocol,
        /** In-container port the game protocol listens on (mapped to a NodePort by PR7). */
        int containerPort,
        /** Optional in-container HTTP console/admin port (be-gateway path-routed), or null. */
        Integer consolePort,
        String summary,
        boolean enabled,
        Instant createdAt,
        String createdBySubject,
        Instant updatedAt) {

    public static final String PROTOCOL_TCP = "tcp";
    public static final String PROTOCOL_UDP = "udp";
    public static final String PROTOCOL_BOTH = "both";
    public static final String PROTOCOL_NONE = "none";
}
