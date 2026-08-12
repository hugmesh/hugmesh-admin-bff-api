package net.hugmesh.adminbff.routeaccess;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * SELF-HEALING reconcile for the Cassandra route-access mirror. Postgres
 * {@code gateway_route_access} is authoritative; each add/remove best-effort mirrors
 * the change into the Cassandra table the gateways poll (see {@link RouteAccessService}
 * + {@link CassandraRouteMirror}). That per-write mirror SWALLOWS failures — the
 * authoritative Postgres write must never fail on a transient Cassandra blip — but the
 * gateways poll the Cassandra snapshot on a fixed interval (≈5 s) with NO on-demand
 * invalidation. So a PERSISTENT mirror-write failure leaves a STALE rule in force on
 * the gateways (an over-grant or over-deny on {@code /api/admin/**}, {@code /api/games/**},
 * {@code /_matrix/**}) until the next successful poll — which never re-derives the
 * MISSED change because the mirror row was never written.
 *
 * <p>This scheduled loop closes that gap FOR ADDED/EDITED rules: every tick it
 * RE-UPSERTS the full authoritative Postgres rule set into the Cassandra mirror, so a
 * transiently-failed per-write mirror <em>write</em> self-heals within one cycle (the
 * gateways then pick up the corrected snapshot on their next poll). The re-upsert is
 * idempotent (same id → same row), so a tick that races a fresh add/remove simply
 * rewrites identical values.
 *
 * <h3>Scope — upsert THEN a GUARDED prune (G4 closes the delete side)</h3>
 * The upsert pass above re-mirrors only rules that still EXIST in Postgres. On its own
 * it does NOT remove orphan mirror rows whose authoritative Postgres rule was DELETED,
 * so a persistently-swallowed per-write {@code mirror.delete} (the best-effort remove
 * path in {@link RouteAccessService}) could leave a removed-in-Postgres rule live in the
 * Cassandra snapshot — and if that stale rule is {@code allow=true} it lingers as an
 * over-grant. G4 adds a SECOND pass that closes that gap: after the upsert pass it reads
 * {@link RouteMirror#listIds()} and DELETES every mirror id with no matching
 * authoritative Postgres id (orphan = mirrorIds − postgresIds), best-effort per id.
 *
 * <h4>The guard is the whole point — prune ONLY on a trusted, NON-EMPTY Postgres read</h4>
 * A naive prune on a transiently empty/failed Postgres read would MASS-EVICT live rules
 * from the gateways. So the prune is guarded to fire ONLY when the {@code repo.list()}
 * read SUCCEEDED <em>and</em> returned a NON-EMPTY id set:
 * <ul>
 *   <li>{@code repo.list()} errored → the whole pass is swallowed → NO prune.</li>
 *   <li>{@code repo.list()} returned ZERO ids → NO prune (a transiently-empty or
 *       partially-failed read must never mass-evict the mirror).</li>
 *   <li>{@link RouteMirror#listIds()} errored/empty → NO deletes (it is itself
 *       best-effort, yielding an empty {@link Flux} on failure).</li>
 * </ul>
 * This is deliberately SAFETY OVER COMPLETENESS: a LEGITIMATELY-empty ruleset is simply
 * never pruned (its orphans, if any, are left in place rather than risk evicting live
 * rules on a read that only <em>looks</em> empty). The upsert pass runs FIRST so a rule
 * present in both stores is re-mirrored and never a prune candidate. This never created
 * an authz-bypass today because gateway enforcement re-derives from authoritative
 * Postgres; the Cassandra snapshot is a poll cache (it also deliberately omits
 * {@code domain}/{@code mfa_required}, which the gateway derives/enforces from the token
 * issuer + Postgres, not this mirror). The prune is flag-gated behind
 * {@code app.mirror.cassandra.reconcile.prune-orphans} (DEFAULT true, so the gap is
 * closed by default); the empty/failed-read guard applies REGARDLESS of the flag.
 *
 * <h3>Clones the suspension/backup reconcile pattern EXACTLY</h3>
 * Same {@code @Scheduled} fixed-delay tick, the same {@link LeaderElection} single-writer
 * gate ({@code AlwaysLeader} for a single replica / dev / test / CI; the k8s {@code Lease}
 * when {@code app.access-suspension.lease.enabled=true}), {@code runOnce}, and best-effort
 * error-swallow so a tick failure simply retries next tick (the loop never dies).
 *
 * <h3>Safe when Cassandra is absent</h3>
 * The reconciler drives {@link RouteMirror#upsert} — the SAME best-effort path the
 * per-write mirror uses. When {@code app.mirror.cassandra.enabled=false} (or Cassandra is
 * unreachable) every upsert is a logged no-op, so this loop is harmless on a mirror-less
 * dev/test/CI run. The reconciler bean is itself registered ONLY when the mirror is
 * enabled (see {@link RouteMirrorReconcilerConfig}), so with the mirror off the
 * {@code @Scheduled} tick does not even exist.
 */
public class RouteMirrorReconciler {

    private static final Logger log = LoggerFactory.getLogger(RouteMirrorReconciler.class);

    private final RouteAccessRepository repo;
    private final RouteMirror mirror;
    private final LeaderElection leader;

    /** G4: whether the guarded delete-reconcile (orphan prune) pass runs. DEFAULT true
     *  (the delete-side over-grant gap is closed by default). The empty/failed-read guard
     *  in {@link #runOnce()} applies REGARDLESS of this flag. */
    private final boolean pruneOrphans;

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    /** Back-compat ctor (prune ON by default — the gap is closed unless explicitly disabled). */
    public RouteMirrorReconciler(RouteAccessRepository repo, RouteMirror mirror, LeaderElection leader) {
        this(repo, mirror, leader, true);
    }

    public RouteMirrorReconciler(RouteAccessRepository repo, RouteMirror mirror, LeaderElection leader,
                                 boolean pruneOrphans) {
        this.repo = repo;
        this.mirror = mirror;
        this.leader = leader;
        this.pruneOrphans = pruneOrphans;
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.mirror.cassandra.reconcile.interval-ms:60000}",
            initialDelayString = "${app.mirror.cassandra.reconcile.initial-delay-ms:15000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    /**
     * One reconcile pass: (1) re-upsert the FULL authoritative Postgres rule set into the
     * Cassandra mirror, THEN (2) run the GUARDED orphan-prune. Skips entirely when not the
     * leader (single-writer). The Postgres read failure is SWALLOWED (logged) so a tick
     * failure simply retries on the next tick and the scheduled loop never dies; each
     * per-rule mirror upsert/delete is ALREADY best-effort (a Cassandra blip on one row
     * never aborts the rest of the pass).
     *
     * <p>The upsert pass runs FIRST and, as it streams {@code repo.list()}, COLLECTS the
     * authoritative Postgres id set. The prune pass then fires ONLY when that read
     * SUCCEEDED and returned a NON-EMPTY id set (see the guard in {@link #prune}). Because
     * the whole chain is wrapped in one {@code onErrorResume}, a {@code repo.list()} error
     * short-circuits BOTH passes (no prune on a failed read). Returns the count of rules
     * re-mirrored this pass (the upsert count; the prune count is logged).
     */
    public Mono<Long> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[route-mirror-reconciler] not leader ({}) — skipping tick", leader.label());
            return Mono.just(0L);
        }
        Set<String> postgresIds = new LinkedHashSet<>();
        return repo.list()
                // mirror.upsert is best-effort (swallows its own Cassandra failures), so
                // one unreachable-Cassandra rule never aborts the rest of the re-mirror.
                // We also record each authoritative id for the guarded prune below.
                .concatMap(rule -> {
                    postgresIds.add(rule.id());
                    return mirror.upsert(rule).thenReturn(1L);
                })
                .reduce(0L, Long::sum)
                .doOnNext(n -> log.debug("[route-mirror-reconciler] re-mirrored {} route rule(s)", n))
                // THEN the guarded delete-reconcile. Runs only after the upsert pass
                // completes (so a rule in BOTH stores was already re-mirrored and is never a
                // prune candidate) and only reached when repo.list() SUCCEEDED.
                .flatMap(upserted -> prune(postgresIds).thenReturn(upserted))
                .onErrorResume(e -> {
                    log.warn("[route-mirror-reconciler] reconcile failed (will retry next tick): {}",
                            e.toString());
                    return Mono.just(0L);
                });
    }

    /**
     * GUARDED orphan-prune (G4). Deletes every mirror id with no matching authoritative
     * Postgres id — but ONLY when it is SAFE to do so:
     * <ul>
     *   <li>flag off → skip;</li>
     *   <li>{@code postgresIds} EMPTY → skip (a transiently-empty/failed Postgres read must
     *       NEVER mass-evict the mirror; SAFETY OVER COMPLETENESS — a legitimately-empty
     *       ruleset is simply not pruned);</li>
     *   <li>a {@code repo.list()} ERROR never reaches here (it short-circuits {@link #runOnce}
     *       before the prune).</li>
     * </ul>
     * {@link RouteMirror#listIds()} is itself best-effort (empty {@link Flux} on failure), so
     * a failed/empty mirror read yields NO deletes. Each {@code mirror.delete} is best-effort;
     * a prune failure is swallowed (logged) and the loop never dies. Idempotent: an id already
     * pruned is simply absent from the next {@code listIds()}.
     */
    private Mono<Long> prune(Set<String> postgresIds) {
        if (!pruneOrphans) {
            log.debug("[route-mirror-reconciler] orphan-prune disabled — skipping prune pass");
            return Mono.just(0L);
        }
        // THE GUARD: never prune on an empty authoritative set (transiently-empty/failed read).
        if (postgresIds.isEmpty()) {
            log.debug("[route-mirror-reconciler] authoritative Postgres id set is EMPTY — "
                    + "skipping prune (no mass-eviction on an empty/failed read)");
            return Mono.just(0L);
        }
        return mirror.listIds()
                // orphan = mirrorId NOT in the authoritative Postgres id set.
                .filter(id -> !postgresIds.contains(id))
                // mirror.delete is best-effort (swallows its own Cassandra failures), so one
                // unreachable-Cassandra delete never aborts the rest of the prune.
                .concatMap(id -> {
                    log.info("[route-mirror-reconciler] pruning orphan mirror row id={} "
                            + "(no authoritative Postgres rule)", id);
                    return mirror.delete(id).thenReturn(1L);
                })
                .reduce(0L, Long::sum)
                .doOnNext(n -> log.info("[route-mirror-reconciler] pruned {} orphan mirror row(s)", n))
                .onErrorResume(e -> {
                    log.warn("[route-mirror-reconciler] orphan-prune failed (will retry next tick): {}",
                            e.toString());
                    return Mono.just(0L);
                });
    }
}
