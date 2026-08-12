package net.hugmesh.adminbff.gamesservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.CreateGameInstanceRequest;

import java.time.Duration;
import java.time.Instant;
import java.util.regex.Pattern;

/**
 * The per-domain instance CRUD surface for the games app-store, enforcing the SUPERADMIN
 * CREATION GATE + the {@link PrincipalDomain} tenant boundary.
 *
 * <h3>Creation gate (fail-closed 403)</h3>
 * Before a {@code game_instance} row is written, {@link #create} checks the
 * {@link GameServerDomainOffer} for the caller's (domain, slug):
 * <ol>
 *   <li>an offer row must EXIST and be {@code offered_by_superadmin=true} (TIER-1: the
 *       superadmin must have offered this server to this domain) — else 403;</li>
 *   <li>the offer must be {@code enabled_by_admin=true} (TIER-2: the domain admin enabled
 *       it) — else 403;</li>
 *   <li>the count of NON-TERMINAL instances for (domain, slug) must be {@code <
 *       max_instances} (the quota) — else 403.</li>
 * </ol>
 * Everything is keyed to the caller's OWN domain (from the validated issuer) — a caller can
 * never create in another brand.
 *
 * <h3>Role split (enforced at the controller)</h3>
 * {@code create} is gated {@code ROLE_GAMES_SERVICES_ADMIN}; {@code suspend}/{@code resume}/
 * {@code terminate} are gated {@code ROLE_GAMES_SERVICES_ADMIN} OR
 * {@code ROLE_GAMES_SERVICES_RUNNER} (mod-delegated run/stop). The service is unaware of the
 * role — it trusts the controller gate + scopes by domain.
 *
 * <p>Lifecycle writes are desired-state only: the row is set to {@code pending}/
 * {@code suspended}/{@code terminated}; the Lease-gated {@link GameInstanceReconciler}
 * effects the cluster change (render/teardown). Mirrors the SuspensionService idiom (the
 * only write surface; the loop is the effector).
 */
@Service
public class GameInstanceService {

    private static final Logger log = LoggerFactory.getLogger(GameInstanceService.class);

    /** DNS-label-ish instance name (the workload name is derived from it). */
    private static final Pattern NAME = Pattern.compile("^[a-z0-9][a-z0-9-]{0,62}$");

    private final GameInstanceRepository instances;
    private final GameServerDomainOfferRepository offers;
    private final GameServerCatalogRepository catalog;

    public GameInstanceService(GameInstanceRepository instances,
                               GameServerDomainOfferRepository offers,
                               GameServerCatalogRepository catalog) {
        this.instances = instances;
        this.offers = offers;
        this.catalog = catalog;
    }

    /** List instances visible to the caller's scope (own brand; superadmin all). */
    public Flux<GameInstance> list(PrincipalDomain scope) {
        return instances.findAll(scope);
    }

    public Mono<GameInstance> get(String id, PrincipalDomain scope) {
        return instances.findById(id, scope)
                .switchIfEmpty(Mono.error(ApiException.notFound("no instance '" + id + "'")));
    }

    /**
     * The instance + its catalog entry (for connection info: protocol + ports), scoped to
     * the caller's brand. Returns a tuple so the controller can build the connection DTO.
     */
    public Mono<reactor.util.function.Tuple2<GameInstance, GameServerCatalogEntry>> connection(
            String id, PrincipalDomain scope) {
        return get(id, scope).flatMap(i -> catalog.findBySlug(i.slug())
                // The catalog entry may be soft-removed; still return the instance with a
                // null entry so the caller gets the ports it knows.
                .map(entry -> reactor.util.function.Tuples.of(i, entry))
                .switchIfEmpty(Mono.fromSupplier(() ->
                        reactor.util.function.Tuples.of(i, (GameServerCatalogEntry) null))));
    }

    /**
     * Create (request) a new instance in the caller's OWN domain, enforcing the creation
     * gate. The owner is the caller's subject (owner == subject). Fail-closed: an unscoped
     * caller (NO_DOMAIN) can satisfy no offer, so it 403s.
     */
    public Mono<GameInstance> create(CreateGameInstanceRequest req, String ownerSubject,
                                     PrincipalDomain scope) {
        String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
        String slug = trim(req.slug());
        String name = trim(req.name());
        if (slug == null || slug.isBlank()) {
            return Mono.error(ApiException.badRequest("slug is required"));
        }
        if (name == null || !NAME.matcher(name).matches()) {
            return Mono.error(ApiException.badRequest(
                    "name must be a DNS label (lowercase alnum + '-', <=63 chars)"));
        }
        Instant endingAt = req.ttlSeconds() == null
                ? null : Instant.now().plus(Duration.ofSeconds(req.ttlSeconds()));

        // THE CREATION GATE — offer must exist, be superadmin-offered, admin-enabled, and
        // the (domain,slug) quota must have headroom. Each failure is a fail-closed 403.
        return offers.find(domain, slug)
                .switchIfEmpty(Mono.error(ApiException.forbidden(
                        "'" + slug + "' is not offered to this domain")))
                // Gate on offer flags then look up the catalog entry and enforce quota.
                .flatMap(offer -> checkOfferAndCreate(offer, domain, slug, name, ownerSubject, endingAt));
    }

    /** Validate offer flags, verify catalog entry is enabled, then enforce quota. */
    private Mono<GameInstance> checkOfferAndCreate(GameServerDomainOffer offer, String domain,
                                                    String slug, String name, String ownerSubject,
                                                    Instant endingAt) {
        if (!offer.offeredBySuperadmin()) {
            return Mono.error(ApiException.forbidden("'" + slug + "' offer is withdrawn by the superadmin"));
        }
        if (!offer.enabledByAdmin()) {
            return Mono.error(ApiException.forbidden("'" + slug + "' is not enabled for this domain"));
        }
        return catalog.findBySlug(slug)
                .switchIfEmpty(Mono.error(ApiException.forbidden("'" + slug + "' is no longer in the catalog")))
                .flatMap(entry -> entry.enabled()
                        ? enforceQuotaThenInsert(domain, slug, name, ownerSubject, endingAt, offer.maxInstances())
                        : Mono.error(ApiException.forbidden("'" + slug + "' is soft-disabled in the catalog")));
    }

    private Mono<GameInstance> enforceQuotaThenInsert(String domain, String slug, String name,
                                                      String ownerSubject, Instant endingAt,
                                                      int maxInstances) {
        return instances.countNonTerminal(domain, slug)
                // Check quota then idempotently insert, with a duplicate-key race backstop.
                .flatMap(count -> insertIfQuotaAllows(count, maxInstances, domain, slug, name,
                        ownerSubject, endingAt));
    }

    /** Reject if over quota; otherwise idempotently insert with a race-backstop. */
    private Mono<GameInstance> insertIfQuotaAllows(long count, int maxInstances, String domain,
                                                    String slug, String name, String ownerSubject,
                                                    Instant endingAt) {
        if (count >= maxInstances) {
            return Mono.error(ApiException.forbidden(
                    "instance quota reached for '" + slug + "' in this domain ("
                    + count + "/" + maxInstances + ")"));
        }
        // Idempotency: a live instance with the same name is a 409 (the partial
        // unique index is the race backstop on Postgres).
        return instances.findNonTerminal(domain, slug, name)
                .flatMap(existing -> Mono.<GameInstance>error(ApiException.conflict(
                        "instance '" + name + "' already exists for '" + slug + "'")))
                .switchIfEmpty(Mono.defer(() ->
                        instances.insertPending(domain, slug, name, ownerSubject, endingAt)
                                .doOnNext(i -> log.info(
                                        "[games-instance] requested {}/{}/{} by={} ttl={} (id={})",
                                        domain, slug, name, ownerSubject, endingAt, i.id()))
                                .onErrorResume(e -> instances.findNonTerminal(domain, slug, name)
                                        .flatMap(now -> Mono.<GameInstance>error(ApiException.conflict(
                                                "instance '" + name + "' already exists for '" + slug + "'")))
                                        .switchIfEmpty(Mono.error(e)))));
    }

    /** Suspend (pause) a running instance — scoped to the caller's brand. */
    public Mono<GameInstance> suspend(String id, PrincipalDomain scope) {
        return transition(id, scope, GameInstance.STATE_SUSPENDED,
                GameInstance.STATE_ACTIVE, GameInstance.STATE_PENDING);
    }

    /** Resume a suspended instance back to pending (the reconciler re-renders it). */
    public Mono<GameInstance> resume(String id, PrincipalDomain scope) {
        return transition(id, scope, GameInstance.STATE_PENDING, GameInstance.STATE_SUSPENDED);
    }

    /** Terminate (teardown) an instance — scoped to the caller's brand. Never deletes. */
    public Mono<GameInstance> terminate(String id, PrincipalDomain scope) {
        return transition(id, scope, GameInstance.STATE_TERMINATED,
                GameInstance.STATE_PENDING, GameInstance.STATE_ACTIVE, GameInstance.STATE_SUSPENDED);
    }

    private Mono<GameInstance> transition(String id, PrincipalDomain scope, String toState,
                                          String... fromStates) {
        // Resolve WITHIN scope first so a scoped caller can never touch another brand's row.
        return instances.findById(id, scope)
                .switchIfEmpty(Mono.error(ApiException.notFound("no instance '" + id + "'")))
                .flatMap(i -> instances.casState(i.id(), toState, fromStates)
                        .flatMap(rows -> (rows == null || rows == 0)
                                ? Mono.<GameInstance>error(ApiException.conflict(
                                        "instance '" + id + "' is not in a state that allows "
                                        + toState + " (current=" + i.state() + ")"))
                                : instances.findById(i.id()))
                        .doOnNext(updated -> log.info("[games-instance] {} -> {} (id={})",
                                i.state(), toState, id)));
    }

    private static String trim(String s) {
        return s == null ? null : s.trim();
    }
}
