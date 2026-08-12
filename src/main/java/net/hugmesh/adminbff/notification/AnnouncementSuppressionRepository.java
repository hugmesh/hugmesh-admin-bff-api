package net.hugmesh.adminbff.notification;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code announcement_suppressed} (Liquibase changeset
 * 062) — the minimal per-domain ADMIN kill-switch for the {@code @system} BROADCAST
 * channel. One row per domain; absence of a row = NOT suppressed (fail-open). The
 * toggle is an UPSERT on the {@code domain} primary key.
 *
 * <p>Backed by the Spring Data {@link AnnouncementSuppressionR2dbcRepository} (no raw
 * {@code DatabaseClient}). The upsert is a portable {@code findById}-then-save (INSERT
 * if absent, UPDATE if present) — behaviour-identical to the prior UPDATE-then-INSERT.
 */
@Repository
public class AnnouncementSuppressionRepository {

    private final AnnouncementSuppressionR2dbcRepository repo;

    public AnnouncementSuppressionRepository(AnnouncementSuppressionR2dbcRepository repo) {
        this.repo = repo;
    }

    /** Whether the {@code @system} broadcast channel is suppressed for a domain.
     *  Absence of a row → {@code false} (a never-toggled domain is not suppressed). */
    public Mono<Boolean> isSuppressed(String domain) {
        return repo.findById(domain)
                .map(AnnouncementSuppression::suppressed)
                .defaultIfEmpty(false);
    }

    /**
     * UPSERT the suppression flag for a domain (insert-or-update on the {@code domain}
     * PK). Returns the new flag.
     */
    public Mono<Boolean> setSuppressed(String domain, boolean suppressed, String updatedBy) {
        String by = updatedBy == null ? "admin" : updatedBy;
        return repo.existsById(domain)
                .flatMap(exists -> repo.save(
                        AnnouncementSuppression.of(domain, suppressed, by, !exists)))
                .thenReturn(suppressed);
    }
}
