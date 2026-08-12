package net.hugmesh.adminbff.announcement;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code announcement} (Liquibase changeset 060).
 *
 * <p>Backed by the Spring Data {@link AnnouncementRowRepository} (no raw
 * {@code DatabaseClient}); maps the {@link AnnouncementRow} entity to the {@link
 * Announcement} JSON projection. The ADMIN mutation surface (list/find/insert/update/
 * delete) is domain-scoped; the active-surface + reconcile reads are UNSCOPED (the login
 * feed is public/unauthenticated).
 */
@Repository
public class AnnouncementRepository {

    private final AnnouncementRowRepository repo;

    public AnnouncementRepository(AnnouncementRowRepository repo) {
        this.repo = repo;
    }

    /** Newest-first full list for the ADMIN announcements view (domain-scoped). */
    public Flux<Announcement> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByCreatedAtDesc(domain).map(AnnouncementRow::toDomain);
        }
        return repo.findAllByOrderByCreatedAtDesc().map(AnnouncementRow::toDomain);
    }

    /** Find one announcement by id, scoped to the acting principal's domain. */
    public Mono<Announcement> find(String id, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByIdAndDomain(UUID.fromString(id), domain).map(AnnouncementRow::toDomain);
        }
        return repo.findById(UUID.fromString(id)).map(AnnouncementRow::toDomain);
    }

    /** Unscoped find by id — used internally by insert + the akkoma reconcile loop. */
    Mono<Announcement> findUnscoped(String id) {
        return repo.findById(UUID.fromString(id)).map(AnnouncementRow::toDomain);
    }

    /** Insert a fully-prepared announcement (DB-generated id); returns the new row. The
     *  INSERT omits {@code id} (filled from the {@code gen_random_uuid()} column DEFAULT,
     *  changelog 200) and {@code RETURNING id} hands back the generated UUID, which we
     *  read back DOMAIN-UNSCOPED by that id to return the persisted row (same field
     *  order/values as before). */
    public Mono<Announcement> insert(Announcement a) {
        String domain = (a.domain() == null || a.domain().isBlank()) ? PrincipalDomain.NO_DOMAIN : a.domain();
        LocalDateTime now = LocalDateTime.now();
        return repo.insertReturningId(a.title(), a.bodyHtml(), a.format(), a.state(),
                        a.targetHome(), a.targetLogin(), a.targetAkkoma(), a.targetForum(), a.priority(),
                        AnnouncementRow.toLocal(a.startsAt()), AnnouncementRow.toLocal(a.endsAt()),
                        a.timezone(), a.dismissible(), a.createdBy(), a.akkomaRef(), now, now, domain)
                .flatMap(genId -> repo.findById(genId).map(AnnouncementRow::toDomain));
    }

    /**
     * Replace the editable fields of an existing announcement. {@code akkoma_ref} is
     * managed by {@link #setAkkomaRef}, NOT here; {@code domain}/{@code created_at} are
     * preserved from the existing row. Returns the updated row.
     */
    public Mono<Announcement> update(String id, Announcement a) {
        UUID uuid = UUID.fromString(id);
        return repo.findById(uuid).flatMap(existing -> {
            AnnouncementRow updated = new AnnouncementRow(uuid, a.title(), a.bodyHtml(), a.format(),
                    a.state(), a.targetHome(), a.targetLogin(), a.targetAkkoma(), a.targetForum(),
                    a.priority(), AnnouncementRow.toLocal(a.startsAt()), AnnouncementRow.toLocal(a.endsAt()),
                    a.timezone(), a.dismissible(), existing.createdBy(), existing.akkomaRef(),
                    existing.createdAt(), LocalDateTime.now(), existing.domain(), false);
            return repo.save(updated).map(AnnouncementRow::toDomain);
        });
    }

    /** Record (or clear, with null) the akkoma propagation handle on (un)publish. */
    public Mono<Void> setAkkomaRef(String id, String akkomaRef) {
        return repo.setAkkomaRef(UUID.fromString(id), akkomaRef).then();
    }

    /** Delete an announcement by id, scoped to the acting principal's domain. */
    public Mono<Void> delete(String id, PrincipalDomain scope) {
        UUID uuid = UUID.fromString(id);
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByIdAndDomain(uuid, domain)
                    .flatMap(r -> repo.deleteById(uuid))
                    .then();
        }
        return repo.deleteById(uuid);
    }

    // ── Active-surface queries ──────────────────────────────────────────
    public Flux<Announcement> activeForHome(Instant now) {
        return repo.activeForHome(AnnouncementRow.toLocal(now)).map(AnnouncementRow::toDomain);
    }

    public Flux<Announcement> activeForLogin(Instant now) {
        return repo.activeForLogin(AnnouncementRow.toLocal(now)).map(AnnouncementRow::toDomain);
    }

    public Flux<Announcement> activeForForum(Instant now) {
        return repo.activeForForum(AnnouncementRow.toLocal(now)).map(AnnouncementRow::toDomain);
    }

    /** Published, akkoma-targeted announcements that should no longer have a live post. */
    public Flux<Announcement> expiredWithAkkomaRef(Instant now) {
        return repo.expiredWithAkkomaRef(AnnouncementRow.toLocal(now)).map(AnnouncementRow::toDomain);
    }
}
