package net.hugmesh.adminbff.desktop;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code desktop_app_catalog} (changeset 140). The
 * scoped/unscoped lists, the by-(domain,ref) reads, the scoped by-id read, and the enabled-only
 * registry reads are derived finders; the scoped/unscoped {@code enabled} partial UPDATEs and
 * the scoped/unscoped DELETEs are {@code @Query} static-final constants (a partial UPDATE
 * stamping {@code updated_at} and a scoped DELETE are not derivable). The
 * {@link DesktopAppCatalogRepository} facade maps rows to/from the {@link DesktopAppCatalogEntry}
 * domain record.
 */
public interface DesktopAppCatalogR2dbcRepository
        extends ReactiveCrudRepository<DesktopAppCatalogRow, String> {

    /**
     * Insert a new catalog row with a DB-generated id (changelog 200): {@code id} is OMITTED →
     * filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads
     * the generated varchar(36) back ({@code Mono<String>}). The not-yet-set {@code updated_at} is
     * OMITTED (default NULL — the fresh-row shape; ENABLED FALSE is supplied). Columns match the
     * {@link DesktopAppCatalogRow} order (id + updated_at excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO desktop_app_catalog \
            (app_ref, display_name, source, enabled, added_by, domain, created_at) \
            VALUES (:appRef, :displayName, :source, :enabled, :addedBy, :domain, :createdAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("appRef") String appRef,
                                   @Param("displayName") String displayName,
                                   @Param("source") String source,
                                   @Param("enabled") boolean enabled,
                                   @Param("addedBy") String addedBy,
                                   @Param("domain") String domain,
                                   @Param("createdAt") Instant createdAt);

    /** Catalog rows for a brand, by display name — the scoped admin curation read. */
    Flux<DesktopAppCatalogRow> findByDomainOrderByDisplayName(String domain);

    /** ALL catalog rows (unscoped SUPERADMIN), domain then display name. */
    Flux<DesktopAppCatalogRow> findByOrderByDomainAscDisplayNameAsc();

    /** The row for (domain, appRef), if any — the idempotency / conflict check on add. */
    Mono<DesktopAppCatalogRow> findByDomainAndAppRef(String domain, String appRef);

    /** A single row by id within a brand (scoped resolve). */
    Mono<DesktopAppCatalogRow> findByIdAndDomain(String id, String domain);

    /** The ENABLED refs for one domain — the discover registry working set. */
    Flux<DesktopAppCatalogRow> findByDomainAndEnabledTrueOrderByDisplayName(String domain);

    /** Resolve ONE enabled ref for a domain (the registry single-ref fetch authz gate). */
    Mono<DesktopAppCatalogRow> findByDomainAndAppRefAndEnabledTrue(String domain, String appRef);

    /** Flip {@code enabled} for one row in a brand, stamping {@code updated_at}. */
    String SET_ENABLED_SCOPED =
            "UPDATE desktop_app_catalog SET enabled = :en, updated_at = now() "
            + "WHERE id = :id AND domain = :domain";

    @Modifying
    @Query(SET_ENABLED_SCOPED)
    Mono<Long> setEnabledScoped(String id, boolean en, String domain);

    /** Flip {@code enabled} for one row (unscoped SUPERADMIN). */
    String SET_ENABLED_ALL =
            "UPDATE desktop_app_catalog SET enabled = :en, updated_at = now() WHERE id = :id";

    @Modifying
    @Query(SET_ENABLED_ALL)
    Mono<Long> setEnabledAll(String id, boolean en);

    /** Delete one row in a brand (scoped). */
    String DELETE_SCOPED = "DELETE FROM desktop_app_catalog WHERE id = :id AND domain = :domain";

    @Modifying
    @Query(DELETE_SCOPED)
    Mono<Long> deleteScoped(String id, String domain);

    /** Delete one row (unscoped SUPERADMIN). */
    String DELETE_ALL = "DELETE FROM desktop_app_catalog WHERE id = :id";

    @Modifying
    @Query(DELETE_ALL)
    Mono<Long> deleteByIdReturningCount(String id);
}
