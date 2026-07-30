package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST/PUT /bff/superadmin/games-services/catalog[/{slug}]} (SUPERADMIN) —
 * curate one global games-catalog entry (schema 090). On create, {@code slug},
 * {@code displayName}, {@code imageRef} and {@code licenseSpdx} are required (enforced in
 * {@link systems.hugmesh.adminbff.gamesservices.GamesCatalogService}); on update, null
 * fields leave the current value (PATCH-style).
 *
 * <p>{@code imageRef} MUST be digest-pinned ({@code repo@sha256:<64 hex>}) — a tag-only
 * reference is a clean 400 (the service's {@code ImageRef.validate}); arbitrary-container
 * exec containment.
 */
public record GameCatalogEntryRequest(
        @Size(max = 64, message = "slug is too long")
        @Nullable
        String slug,

        @Size(max = 255, message = "displayName is too long")
        @Nullable
        String displayName,

        @Size(max = 512, message = "imageRef is too long")
        @Nullable
        String imageRef,

        @Size(max = 128, message = "licenseSpdx is too long")
        @Nullable
        String licenseSpdx,

        /** {@code tcp}/{@code udp}/{@code both}/{@code none}; defaults udp on create. */
        @Size(max = 8, message = "protocol is too long")
        @Nullable
        String protocol,

        @Nullable
        Integer containerPort,

        @Nullable
        Integer consolePort,

        @Size(max = 1024, message = "summary is too long")
        @Nullable
        String summary,

        /** Desired-state on/off. {@code null} = true on create / unchanged on update;
         *  {@code false} is the SOFT-DISABLE. */
        @Nullable
        Boolean enabled) {
}
