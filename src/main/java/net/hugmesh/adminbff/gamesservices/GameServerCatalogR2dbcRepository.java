package net.hugmesh.adminbff.gamesservices;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code game_server_catalog} (changeset 090). The
 * full/enabled lists and the by-slug lookup are derived finders; the by-slug partial UPDATE
 * (immutable id/slug/created_*; bumps {@code updated_at}) is a {@code @Query} static-final
 * constant. The {@link GameServerCatalogRepository} facade maps rows to/from the
 * {@link GameServerCatalogEntry} domain record.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 * A duplicate {@code slug} still surfaces the UNIQUE-violation (no ON CONFLICT) — the
 * race backstop the service maps to a 409.
 */
public interface GameServerCatalogR2dbcRepository
        extends ReactiveCrudRepository<GameServerCatalogRow, String> {

    /**
     * Insert a new catalog entry with a DB-generated id (id OMITTED → filled from the column
     * DEFAULT; {@code RETURNING id} reads the generated varchar(36) back). The supplied
     * columns match the {@link GameServerCatalogRow} column order (id excluded); {@code
     * console_port} is nullable.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO game_server_catalog \
            (slug, display_name, image_ref, license_spdx, protocol, container_port, \
             console_port, summary, enabled, created_at, created_by_subject, updated_at) \
            VALUES (:slug, :display_name, :image_ref, :license_spdx, :protocol, \
             :container_port, :console_port, :summary, :enabled, :created_at, \
             :created_by_subject, :updated_at) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("slug") String slug,
                                   @Param("display_name") String displayName,
                                   @Param("image_ref") String imageRef,
                                   @Param("license_spdx") String licenseSpdx,
                                   @Param("protocol") String protocol,
                                   @Param("container_port") int containerPort,
                                   @Param("console_port") Integer consolePort,
                                   @Param("summary") String summary,
                                   @Param("enabled") boolean enabled,
                                   @Param("created_at") Instant createdAt,
                                   @Param("created_by_subject") String createdBySubject,
                                   @Param("updated_at") Instant updatedAt);

    /** Every catalog entry, by natural key — the SUPERADMIN list surface. */
    Flux<GameServerCatalogRow> findByOrderBySlug();

    /** Only the {@code enabled} catalog entries, by natural key — offerable servers. */
    Flux<GameServerCatalogRow> findByEnabledTrueOrderBySlug();

    /** The catalog entry with this {@code slug}, if any — the natural-key lookup. */
    Mono<GameServerCatalogRow> findBySlug(String slug);

    /** Update the MUTABLE fields of the entry matched by {@code slug}, bumping updated_at. */
    String UPDATE_BY_SLUG =
            "UPDATE game_server_catalog SET "
            + "display_name = :displayName, image_ref = :imageRef, license_spdx = :licenseSpdx, "
            + "protocol = :protocol, container_port = :containerPort, console_port = :consolePort, "
            + "summary = :summary, enabled = :enabled, updated_at = now() "
            + "WHERE slug = :slug";

    @Modifying
    @Query(UPDATE_BY_SLUG)
    Mono<Long> updateBySlug(String slug, String displayName, String imageRef, String licenseSpdx,
                            String protocol, int containerPort, Integer consolePort, String summary,
                            boolean enabled);
}
