package systems.hugmesh.adminbff.gamesservices;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code game_server_catalog} — the GLOBAL, superadmin-curated
 * FOSS games catalog (schema in Liquibase {@code db/changelog/090-games-server-catalog.xml}).
 * App-generated {@code varchar(36)} UUID ids, never a blocking call.
 *
 * <p>Backed by the Spring Data {@link GameServerCatalogR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link GameServerCatalogRow} entity to/from the
 * {@link GameServerCatalogEntry} domain record.
 *
 * <p>The catalog is the registry OF GAME SERVERS, so every query is UNSCOPED — there is no
 * per-row tenant discriminator; the controller's {@code @PreAuthorize("hasRole('SUPERADMIN')")}
 * (PR2) is the only gate. There is no delete: a server is soft-disabled
 * ({@code enabled=false}) via {@link #update}, never hard-deleted out from under live
 * per-domain offers.
 */
@Repository
public class GameServerCatalogRepository {

    private final GameServerCatalogR2dbcRepository repo;

    public GameServerCatalogRepository(GameServerCatalogR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * Insert a new catalog entry (app-generated id), stamping {@code created_by_subject}
     * and returning the persisted row. {@code slug} is the UNIQUE natural key, so a
     * duplicate surfaces as the DB unique-violation the service maps to a 409 (after its
     * own find-before-insert idempotency check).
     */
    public Mono<GameServerCatalogEntry> insert(GameServerCatalogEntry e, String createdBySubject) {
        Instant now = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id hands back the generated string, which we map into the persisted
        // entry with the SAME field order/values as before.
        return repo.insertReturningId(e.slug(), e.displayName(), e.imageRef(), e.licenseSpdx(),
                        e.protocol(), e.containerPort(), e.consolePort(), e.summary(), e.enabled(),
                        now, createdBySubject, now)
                .map(genId -> new GameServerCatalogEntry(genId, e.slug(), e.displayName(),
                        e.imageRef(), e.licenseSpdx(), e.protocol(), e.containerPort(),
                        e.consolePort(), e.summary(), e.enabled(), now, createdBySubject, now));
    }

    /** Every catalog entry (the SUPERADMIN list surface). Ordered by the natural key. */
    public Flux<GameServerCatalogEntry> findAll() {
        return repo.findByOrderBySlug().map(GameServerCatalogRow::toDomain);
    }

    /** Only the {@code enabled} catalog entries — the source for per-domain offer
     *  surfaces (a soft-disabled server is not offerable). Ordered by the natural key. */
    public Flux<GameServerCatalogEntry> findEnabled() {
        return repo.findByEnabledTrueOrderBySlug().map(GameServerCatalogRow::toDomain);
    }

    /** The catalog entry with this {@code slug}, if any — the natural-key lookup. */
    public Mono<GameServerCatalogEntry> findBySlug(String slug) {
        return repo.findBySlug(slug).map(GameServerCatalogRow::toDomain);
    }

    /**
     * Update the MUTABLE fields of an existing catalog entry (matched by {@code slug}) and
     * re-read the row. The PK ({@code id}), the {@code slug} natural key, {@code created_at}
     * and {@code created_by_subject} are IMMUTABLE — only the descriptors and {@code enabled}
     * change (and {@code updated_at} is bumped). Empty if no entry with that slug exists.
     */
    public Mono<GameServerCatalogEntry> update(GameServerCatalogEntry e) {
        return repo.updateBySlug(e.slug(), e.displayName(), e.imageRef(), e.licenseSpdx(),
                        e.protocol(), e.containerPort(), e.consolePort(), e.summary(), e.enabled())
                .flatMap(n -> n == 0 ? Mono.empty() : findBySlug(e.slug()));
    }
}
