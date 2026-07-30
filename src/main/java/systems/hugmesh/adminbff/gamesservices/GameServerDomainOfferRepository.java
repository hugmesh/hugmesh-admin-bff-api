package systems.hugmesh.adminbff.gamesservices;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code game_server_domain_offer} — the per-({@code domain},
 * catalog {@code slug}) TWO-TIER offer (schema in Liquibase
 * {@code db/changelog/090-games-server-catalog.xml}).
 *
 * <p>Backed by the Spring Data {@link GameServerDomainOfferR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link GameServerDomainOfferRow} entity to/from the
 * {@link GameServerDomainOffer} domain record.
 *
 * <p>Carries a {@code domain} tenant discriminator and follows the SCOPE-BRANCH idiom: a
 * SCOPED admin sees/mutates only their own brand's offer rows ({@code WHERE domain = :domain});
 * SUPERADMIN (unscoped) sees/mutates every brand's rows. Fail-closed: a null scope is the
 * {@link PrincipalDomain#NO_DOMAIN} sentinel (matches nothing).
 *
 * <p>There is no delete: an offer is withdrawn by setting {@code offered_by_superadmin}
 * (or {@code enabled_by_admin}) to {@code false} via {@link #update}.
 */
@Repository
public class GameServerDomainOfferRepository {

    private final GameServerDomainOfferR2dbcRepository repo;

    public GameServerDomainOfferRepository(GameServerDomainOfferR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * Insert a new offer row (app-generated id, the SUPERADMIN OFFER step). {@code (domain,
     * slug)} is UNIQUE, so a duplicate surfaces as the DB unique-violation the service maps
     * to a 409 (after its own find-before-insert check).
     */
    public Mono<GameServerDomainOffer> insert(GameServerDomainOffer o, String createdBySubject) {
        Instant now = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id hands back the generated string, which we map into the persisted
        // offer with the SAME field order/values as before.
        return repo.insertReturningId(o.domain(), o.slug(), o.offeredBySuperadmin(),
                        o.enabledByAdmin(), o.maxInstances(), now, createdBySubject, now)
                .map(genId -> new GameServerDomainOffer(genId, o.domain(), o.slug(),
                        o.offeredBySuperadmin(), o.enabledByAdmin(), o.maxInstances(),
                        now, createdBySubject, now));
    }

    /**
     * Every offer VISIBLE to the given tenant scope — a SCOPED admin sees only their brand's
     * offers ({@code WHERE domain = :domain}); SUPERADMIN sees every brand's offers.
     */
    public Flux<GameServerDomainOffer> findAll(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderBySlug(domain).map(GameServerDomainOfferRow::toDomain);
        }
        return repo.findByOrderByDomainAscSlugAsc().map(GameServerDomainOfferRow::toDomain);
    }

    /** Every offer for one explicit domain (the SUPERADMIN per-domain offer surface and
     *  the games-up degrade check). UNSCOPED — the caller has already authorized. */
    public Flux<GameServerDomainOffer> findByDomain(String domain) {
        return repo.findByDomainOrderBySlug(domain).map(GameServerDomainOfferRow::toDomain);
    }

    /**
     * The single offer for a ({@code domain}, {@code slug}) VISIBLE to the given scope — a
     * scoped admin only ever resolves a row in THEIR brand (so it can never enable/run
     * another brand's offer); SUPERADMIN resolves it in any brand.
     */
    public Mono<GameServerDomainOffer> find(String domain, String slug, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String scopedDomain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainAndSlug(scopedDomain, slug).map(GameServerDomainOfferRow::toDomain);
        }
        return repo.findByDomainAndSlug(domain, slug).map(GameServerDomainOfferRow::toDomain);
    }

    /** The single offer for a ({@code domain}, {@code slug}), UNSCOPED — for the instance
     *  creation-gate (PR6) which has already resolved the caller's own domain. */
    public Mono<GameServerDomainOffer> find(String domain, String slug) {
        return repo.findByDomainAndSlug(domain, slug).map(GameServerDomainOfferRow::toDomain);
    }

    /**
     * Update the MUTABLE flags/quota of an offer (matched by {@code (domain, slug)}) and
     * re-read it. {@code id}, {@code domain}, {@code slug}, {@code created_at} and
     * {@code created_by_subject} are IMMUTABLE. Empty if no such offer exists.
     */
    public Mono<GameServerDomainOffer> update(GameServerDomainOffer o) {
        return repo.updateByDomainAndSlug(o.domain(), o.slug(), o.offeredBySuperadmin(),
                        o.enabledByAdmin(), o.maxInstances())
                .flatMap(n -> n == 0 ? Mono.empty() : find(o.domain(), o.slug()));
    }
}
