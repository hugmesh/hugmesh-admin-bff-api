package net.hugmesh.adminbff.gamesservices;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

/**
 * Reactive (R2DBC) store for {@code game_instance} — the desired-state table the
 * single-writer instance reconcile loop reads/writes (schema in Liquibase
 * {@code db/changelog/091-game-instance.xml}). App-generated UUID ids, CAS state transitions
 * (never DELETE — the row is the audit), and the {@link PrincipalDomain} scope-branch on the
 * admin read surface.
 *
 * <p>Backed by the Spring Data {@link GameInstanceR2dbcRepository} (no raw {@code DatabaseClient});
 * maps the {@link GameInstanceRow} entity to/from the {@link GameInstance} domain record.
 */
@Repository
public class GameInstanceRepository {

    /** The non-terminal state set (pending/active/suspended) — the idempotency / quota filter. */
    private static final List<String> NON_TERMINAL = List.of(
            GameInstance.STATE_PENDING, GameInstance.STATE_ACTIVE, GameInstance.STATE_SUSPENDED);

    private final GameInstanceR2dbcRepository repo;

    public GameInstanceRepository(GameInstanceR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * Insert a new PENDING instance (app-generated id), returning it. The caller is
     * expected to have checked for an existing non-terminal row first; the partial unique
     * index is the backstop against a race.
     */
    public Mono<GameInstance> insertPending(String domain, String slug, String name,
                                            String ownerSubject, Instant endingAt) {
        Instant now = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id hands back the generated string, which we map into the persisted
        // GameInstance with the SAME field order/values as before (namespace/port/path NULL).
        return repo.insertReturningId(domain, slug, name, GameInstance.STATE_PENDING,
                        GameInstance.PROP_PENDING, ownerSubject, now, endingAt, now)
                .map(genId -> new GameInstance(genId, domain, slug, name,
                        GameInstance.STATE_PENDING, GameInstance.PROP_PENDING, ownerSubject,
                        now, endingAt, null, null, null, now));
    }

    /** A single instance by id (UNSCOPED) — the reconcile loop / internal use. */
    public Mono<GameInstance> findById(String id) {
        return repo.findById(id).map(GameInstanceRow::toDomain);
    }

    /** A single instance by id VISIBLE to the given scope — a scoped admin only resolves a
     *  row in THEIR brand (so it can never act on another brand's instance). */
    public Mono<GameInstance> findById(String id, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByIdAndDomain(id, domain).map(GameInstanceRow::toDomain);
        }
        return findById(id);
    }

    /** The non-terminal instance for a (domain, slug, name), if any — the idempotency check. */
    public Mono<GameInstance> findNonTerminal(String domain, String slug, String name) {
        return repo.findByDomainAndSlugAndNameAndStateIn(domain, slug, name, NON_TERMINAL)
                .map(GameInstanceRow::toDomain);
    }

    /** Count NON-TERMINAL instances for a (domain, slug) — the quota check (PR6). */
    public Mono<Long> countNonTerminal(String domain, String slug) {
        return repo.countByDomainAndSlugAndStateIn(domain, slug, NON_TERMINAL)
                .map(c -> c == null ? 0L : c);
    }

    /** All instances VISIBLE to the given scope — the ADMIN read surface. Scoped admin sees
     *  only their brand; SUPERADMIN sees all. Fail-closed null scope -> NO_DOMAIN. */
    public Flux<GameInstance> findAll(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderBySlugAscNameAsc(domain).map(GameInstanceRow::toDomain);
        }
        return repo.findByOrderByDomainAscSlugAscNameAsc().map(GameInstanceRow::toDomain);
    }

    /** All ACTIVE instances for a domain (the per-domain ConfigMap render working set).
     *  UNSCOPED — the reconcile loop renders every brand's ConfigMap. */
    public Flux<GameInstance> activeByDomain(String domain) {
        return repo.findByDomainAndStateOrderBySlugAscNameAsc(domain, GameInstance.STATE_ACTIVE)
                .map(GameInstanceRow::toDomain);
    }

    /** Every domain that currently has at least one ACTIVE instance (the render targets). */
    public Flux<String> domainsWithActive() {
        return repo.domainsInState(GameInstance.STATE_ACTIVE);
    }

    /**
     * The expiry working set: ACTIVE instances whose TTL has passed. Instances with no TTL
     * (ending_at NULL) are excluded and never auto-terminate.
     */
    public Flux<GameInstance> dueForExpiry(Instant now) {
        return repo.dueForExpiry(now).map(GameInstanceRow::toDomain);
    }

    /**
     * Compare-and-swap to a new state for one row id, guarded on a current-state set so only
     * ONE writer wins the transition (returns rows-updated: 1 = won, 0 = already moved).
     */
    public Mono<Long> casState(String id, String toState, String... fromStates) {
        return repo.casState(id, toState, Arrays.asList(fromStates));
    }

    /** Record the ConfigMap-render-leg outcome (pending/applied/failed) for a row. */
    public Mono<Long> updatePropagationState(String id, String propagationState) {
        return repo.updatePropagationState(id, propagationState);
    }

    /** Every node_port currently held by a NON-TERMINAL instance (the allocator's
     *  in-use set; a terminated instance frees its port). UNSCOPED — the NodePort pool is
     *  cluster-wide (a single L4 range, not per-domain), so allocation must see all brands. */
    public Flux<Integer> allocatedNodePorts() {
        return repo.allocatedNodePorts();
    }

    /**
     * Assign a node_port + console_path to an instance, guarded so it only writes when the
     * row still has NO node_port (so a concurrent allocation cannot clobber an existing
     * assignment). Returns rows-updated (1 = this allocation won, 0 = already had a port).
     */
    public Mono<Long> assignPortAndConsole(String id, int nodePort, String consolePath) {
        return repo.assignPortAndConsole(id, nodePort, consolePath);
    }

    /** Assign the namespace to an instance (the games-instances ns, set on first render). */
    public Mono<Long> assignNamespace(String id, String namespace) {
        return repo.assignNamespace(id, namespace);
    }
}
