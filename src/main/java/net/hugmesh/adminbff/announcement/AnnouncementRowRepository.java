package net.hugmesh.adminbff.announcement;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Reactive (R2DBC) Spring Data store for {@code announcement} (changeset 060 + 061).
 * Derived finders cover the admin list (scoped + unscoped) and the scoped/unscoped find;
 * the active-surface window queries (per surface), the expiry sweep, and the
 * akkoma-ref partial UPDATE are {@code @Query} static-final constants (window predicate +
 * priority-DESC ordering + the multi-OR expiry are not derivable). The {@link
 * AnnouncementRepository} facade maps rows to/from {@link Announcement}.
 *
 * <p>DB-GENERATED UUID PK (changelog 200): the {@code id} is NO LONGER minted in Java. The
 * {@code announcement.id} column carries a {@code DEFAULT gen_random_uuid()} (pgcrypto), so
 * the INSERT OMITS {@code id} and appends {@code RETURNING id} to read the database-generated
 * UUID back. The INSERT is an explicit {@code @Query} (the deterministic, mod-bff-proven
 * path) returning {@code Mono<UUID>} rather than a {@code save()} with an assigned id.
 */
public interface AnnouncementRowRepository extends ReactiveCrudRepository<AnnouncementRow, UUID> {

    /** Newest-first list for a brand ({@code WHERE domain=? ORDER BY created_at DESC}). */
    Flux<AnnouncementRow> findByDomainOrderByCreatedAtDesc(String domain);

    /** Newest-first list across all brands ({@code ORDER BY created_at DESC}). */
    Flux<AnnouncementRow> findAllByOrderByCreatedAtDesc();

    /** One row by id within a brand (scoped admin find). */
    Mono<AnnouncementRow> findByIdAndDomain(UUID id, String domain);

    /**
     * Insert a fully-prepared announcement with a DB-generated id. The {@code id} is OMITTED
     * so Postgres fills it from the {@code gen_random_uuid()} column DEFAULT (changelog 200);
     * {@code RETURNING id} reads the generated UUID back. A plain (non-{@code @Modifying})
     * {@code @Query} returning the new id. Static-final SQL constant per the data-access
     * standard; the 19 supplied columns match the {@link AnnouncementRow} column order
     * (id excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO announcement \
            (title, body_html, format, state, target_home, target_login, target_akkoma, \
             target_forum, priority, starts_at, ends_at, timezone, dismissible, created_by, \
             akkoma_ref, created_at, updated_at, domain) \
            VALUES (:title, :body_html, :format, :state, :target_home, :target_login, \
             :target_akkoma, :target_forum, :priority, :starts_at, :ends_at, :timezone, \
             :dismissible, :created_by, :akkoma_ref, :created_at, :updated_at, :domain) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<UUID> insertReturningId(@Param("title") String title,
                                 @Param("body_html") String bodyHtml,
                                 @Param("format") String format,
                                 @Param("state") String state,
                                 @Param("target_home") boolean targetHome,
                                 @Param("target_login") boolean targetLogin,
                                 @Param("target_akkoma") boolean targetAkkoma,
                                 @Param("target_forum") boolean targetForum,
                                 @Param("priority") int priority,
                                 @Param("starts_at") LocalDateTime startsAt,
                                 @Param("ends_at") LocalDateTime endsAt,
                                 @Param("timezone") String timezone,
                                 @Param("dismissible") boolean dismissible,
                                 @Param("created_by") String createdBy,
                                 @Param("akkoma_ref") String akkomaRef,
                                 @Param("created_at") LocalDateTime createdAt,
                                 @Param("updated_at") LocalDateTime updatedAt,
                                 @Param("domain") String domain);

    // ── active-surface window queries (UNSCOPED — the login feed is public) ──

    String ACTIVE_HOME =
            "SELECT * FROM announcement WHERE state = 'published' AND target_home = true "
            + "AND (starts_at IS NULL OR starts_at <= :now) "
            + "AND (ends_at IS NULL OR ends_at > :now) ORDER BY priority DESC, starts_at";

    @Query(ACTIVE_HOME)
    Flux<AnnouncementRow> activeForHome(LocalDateTime now);

    String ACTIVE_LOGIN =
            "SELECT * FROM announcement WHERE state = 'published' AND target_login = true "
            + "AND (starts_at IS NULL OR starts_at <= :now) "
            + "AND (ends_at IS NULL OR ends_at > :now) ORDER BY priority DESC, starts_at";

    @Query(ACTIVE_LOGIN)
    Flux<AnnouncementRow> activeForLogin(LocalDateTime now);

    String ACTIVE_FORUM =
            "SELECT * FROM announcement WHERE state = 'published' AND target_forum = true "
            + "AND (starts_at IS NULL OR starts_at <= :now) "
            + "AND (ends_at IS NULL OR ends_at > :now) ORDER BY priority DESC, starts_at";

    @Query(ACTIVE_FORUM)
    Flux<AnnouncementRow> activeForForum(LocalDateTime now);

    /** Published+akkoma-targeted rows whose live akkoma post should be reaped (expired). */
    String EXPIRED_WITH_AKKOMA =
            "SELECT * FROM announcement WHERE akkoma_ref IS NOT NULL "
            + "AND (state <> 'published' "
            + "     OR (ends_at IS NOT NULL AND ends_at <= :now) "
            + "     OR (starts_at IS NOT NULL AND starts_at > :now) "
            + "     OR target_akkoma = false)";

    @Query(EXPIRED_WITH_AKKOMA)
    Flux<AnnouncementRow> expiredWithAkkomaRef(LocalDateTime now);

    /** Record (or clear, null) the akkoma propagation handle on (un)publish. */
    String SET_AKKOMA_REF =
            "UPDATE announcement SET akkoma_ref = :ref, updated_at = now() WHERE id = :id";

    @Modifying
    @Query(SET_AKKOMA_REF)
    Mono<Long> setAkkomaRef(UUID id, String ref);
}
