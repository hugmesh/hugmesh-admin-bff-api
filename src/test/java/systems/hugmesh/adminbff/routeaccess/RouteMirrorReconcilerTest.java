package systems.hugmesh.adminbff.routeaccess;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.lease.AlwaysLeader;
import systems.hugmesh.adminbff.lease.LeaderElection;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The self-healing route-mirror reconcile loop ({@link RouteMirrorReconciler}). Postgres
 * is authoritative; the loop re-upserts the full Postgres rule set into the Cassandra
 * mirror each tick so a transiently-failed per-write mirror self-heals within one cycle.
 */
class RouteMirrorReconcilerTest {

    private final RouteAccessRepository repo = mock(RouteAccessRepository.class);
    private final LeaderElection leader = new AlwaysLeader();

    private static RouteRule rule(String id, String urlPattern) {
        return new RouteRule(id, "hugmesh-be-gateway", urlPattern, "ROLE_ADMIN", null, true, "default", false);
    }

    @Test
    void runOnce_reMirrorsTheFullAuthoritativePostgresSet() {
        RouteRule a = rule("id-1", "/api/admin/**");
        RouteRule b = rule("id-2", "/api/games/**");
        RouteRule c = rule("id-3", "/_matrix/**");
        when(repo.list()).thenReturn(Flux.just(a, b, c));
        RouteMirror mirror = mock(RouteMirror.class);
        when(mirror.upsert(any(RouteRule.class))).thenReturn(Mono.empty());
        // Mirror carries exactly the authoritative ids → no orphans → no deletes.
        when(mirror.listIds()).thenReturn(Flux.just("id-1", "id-2", "id-3"));

        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader);

        Long mirrored = reconciler.runOnce().block();

        assertThat(mirrored).isEqualTo(3L);
        verify(mirror).upsert(a);
        verify(mirror).upsert(b);
        verify(mirror).upsert(c);
        // A rule present in BOTH stores is never a prune candidate.
        verify(mirror, never()).delete(any(String.class));
    }

    /**
     * The core self-heal: a rule whose ORIGINAL per-write mirror was swallowed (so the
     * Cassandra row is stale/missing) is recovered by the next reconcile pass. We model the
     * mirror as a tiny in-memory store of the LATEST upserted row per id; the first add
     * "fails" (swallowed → not stored), then a reconcile pass re-upserts it and the row
     * becomes present — i.e. the swallowed failure is recovered.
     */
    @Test
    void runOnce_recoversASwallowedPerWriteMirrorFailure() {
        // Authoritative Postgres has the rule; the mirror "store" started WITHOUT it
        // because the original best-effort upsert failed and was swallowed.
        RouteRule stale = rule("id-stale", "/api/admin/**");
        when(repo.list()).thenReturn(Flux.just(stale));

        Map<String, RouteRule> cassandra = new HashMap<>();
        RouteMirror mirror = new RouteMirror() {
            @Override
            public Mono<Void> upsert(RouteRule r) {
                return Mono.fromRunnable(() -> cassandra.put(r.id(), r));
            }

            @Override
            public Mono<Void> delete(String id) {
                return Mono.fromRunnable(() -> cassandra.remove(id));
            }
        };

        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader);

        // PRECONDITION: the swallowed failure left the mirror stale (row absent).
        assertThat(cassandra).doesNotContainKey("id-stale");

        Long mirrored = reconciler.runOnce().block();

        // The reconcile pass re-mirrored the authoritative row — self-healed.
        assertThat(mirrored).isEqualTo(1L);
        assertThat(cassandra).containsEntry("id-stale", stale);
    }

    @Test
    void runOnce_skipsWhenNotLeader() {
        LeaderElection notLeader = new LeaderElection() {
            @Override public boolean isLeader() {
                return false;
            }

            @Override public String label() {
                return "test-non-leader";
            }
        };
        RouteMirror mirror = mock(RouteMirror.class);
        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, notLeader);

        Long mirrored = reconciler.runOnce().block();

        assertThat(mirrored).isEqualTo(0L);
        verify(repo, never()).list();
        verify(mirror, never()).upsert(any(RouteRule.class));
    }

    /**
     * The loop never dies: a Postgres read failure is swallowed (logged) and the tick
     * returns 0 so the {@code @Scheduled} loop simply retries next tick.
     */
    @Test
    void runOnce_swallowsPostgresReadFailure() {
        when(repo.list()).thenReturn(Flux.error(new IllegalStateException("postgres down")));
        RouteMirror mirror = mock(RouteMirror.class);
        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader);

        Long mirrored = reconciler.runOnce().block();

        assertThat(mirrored).isEqualTo(0L);
        verify(mirror, never()).upsert(any(RouteRule.class));
    }

    /**
     * A per-rule mirror blip on ONE rule (best-effort, swallowed inside the mirror) does
     * not abort the rest of the pass — the remaining rules still get re-mirrored. Models
     * the real {@link CassandraRouteMirror#upsert} contract (it never surfaces an error).
     */
    @Test
    void runOnce_continuesPastABestEffortMirrorNoop() {
        RouteRule a = rule("id-1", "/api/admin/**");
        RouteRule b = rule("id-2", "/api/games/**");
        when(repo.list()).thenReturn(Flux.just(a, b));
        List<String> upserted = new ArrayList<>();
        RouteMirror mirror = new RouteMirror() {
            @Override
            public Mono<Void> upsert(RouteRule r) {
                // Best-effort like CassandraRouteMirror: a Cassandra blip is swallowed to
                // Mono.empty() INSIDE the mirror, so the loop just records and moves on.
                return Mono.fromRunnable(() -> upserted.add(r.id()));
            }

            @Override
            public Mono<Void> delete(String id) {
                return Mono.empty();
            }
        };
        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader);

        Long mirrored = reconciler.runOnce().block();

        assertThat(mirrored).isEqualTo(2L);
        assertThat(upserted).containsExactly("id-1", "id-2");
    }

    /** Belt-and-braces: verifying mock interaction counts for the happy path. */
    @Test
    void runOnce_upsertsEachRuleExactlyOnce() {
        RouteRule a = rule("id-1", "/api/admin/**");
        when(repo.list()).thenReturn(Flux.just(a));
        RouteMirror mirror = mock(RouteMirror.class);
        when(mirror.upsert(any(RouteRule.class))).thenReturn(Mono.empty());
        when(mirror.listIds()).thenReturn(Flux.empty());
        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader);

        reconciler.runOnce().block();

        verify(mirror, times(1)).upsert(a);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // G4 — the GUARDED delete-reconcile (orphan prune).
    // ──────────────────────────────────────────────────────────────────────────────

    /**
     * The core delete-side self-heal: an id present in the mirror but with NO authoritative
     * Postgres rule (a swallowed per-write {@code mirror.delete} left an orphan) is PRUNED,
     * while an id in BOTH stores is re-upserted and NEVER deleted.
     */
    @Test
    void runOnce_prunesOrphanMirrorRowsButNotRulesInBothStores() {
        RouteRule live = rule("id-live", "/api/admin/**");
        when(repo.list()).thenReturn(Flux.just(live));
        RouteMirror mirror = mock(RouteMirror.class);
        when(mirror.upsert(any(RouteRule.class))).thenReturn(Mono.empty());
        // Mirror has the live id PLUS a stale orphan whose Postgres rule was deleted.
        when(mirror.listIds()).thenReturn(Flux.just("id-live", "id-orphan"));
        when(mirror.delete(any(String.class))).thenReturn(Mono.empty());

        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader, true);

        Long mirrored = reconciler.runOnce().block();

        assertThat(mirrored).isEqualTo(1L);
        verify(mirror).upsert(live);
        // ONLY the orphan is pruned; the live id (in both stores) is never deleted.
        verify(mirror).delete("id-orphan");
        verify(mirror, never()).delete("id-live");
    }

    /**
     * ★ THE GUARD: an EMPTY authoritative Postgres set must NEVER mass-evict the mirror —
     * even when {@code listIds()} is non-empty, NO delete fires (a transiently-empty/failed
     * Postgres read is treated as "do not prune"; safety over completeness).
     */
    @Test
    void runOnce_emptyPostgresSet_neverMassEvictsTheMirror() {
        when(repo.list()).thenReturn(Flux.empty());
        RouteMirror mirror = mock(RouteMirror.class);
        // The mirror still holds rows — a naive prune would delete ALL of them.
        when(mirror.listIds()).thenReturn(Flux.just("id-1", "id-2", "id-3"));

        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader, true);

        Long mirrored = reconciler.runOnce().block();

        assertThat(mirrored).isEqualTo(0L);
        verify(mirror, never()).delete(any(String.class));
        // With an empty authoritative set the guard fires BEFORE reading the mirror at all.
        verify(mirror, never()).listIds();
    }

    /**
     * ★ A Postgres read ERROR short-circuits BOTH passes — no prune, no throw, the loop
     * survives (returns normally with 0). {@code listIds()}/{@code delete} are never touched.
     */
    @Test
    void runOnce_postgresReadError_noPruneNoThrow() {
        when(repo.list()).thenReturn(Flux.error(new IllegalStateException("postgres down")));
        RouteMirror mirror = mock(RouteMirror.class);

        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader, true);

        Long mirrored = reconciler.runOnce().block();

        assertThat(mirrored).isEqualTo(0L);
        verify(mirror, never()).listIds();
        verify(mirror, never()).delete(any(String.class));
        verify(mirror, never()).upsert(any(RouteRule.class));
    }

    /**
     * A failed {@code listIds()} read (best-effort → empty {@link Flux}) yields NO deletes,
     * but the upsert pass still ran. Models the {@link CassandraRouteMirror#listIds()}
     * contract (a Cassandra blip surfaces as an empty read, never an error).
     */
    @Test
    void runOnce_mirroredIdsReadEmpty_noDeleteUpsertStillRan() {
        RouteRule a = rule("id-1", "/api/admin/**");
        when(repo.list()).thenReturn(Flux.just(a));
        RouteMirror mirror = mock(RouteMirror.class);
        when(mirror.upsert(any(RouteRule.class))).thenReturn(Mono.empty());
        when(mirror.listIds()).thenReturn(Flux.empty()); // best-effort read yielded nothing

        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader, true);

        Long mirrored = reconciler.runOnce().block();

        assertThat(mirrored).isEqualTo(1L);
        verify(mirror).upsert(a);
        verify(mirror, never()).delete(any(String.class));
    }

    /**
     * The prune pass never dies: if {@code listIds()} surfaces an ERROR (belt-and-braces,
     * even though the real mirror swallows it), the tick still returns the upsert count and
     * no delete fires. The loop survives.
     */
    @Test
    void runOnce_mirroredIdsReadError_swallowedNoDelete() {
        RouteRule a = rule("id-1", "/api/admin/**");
        when(repo.list()).thenReturn(Flux.just(a));
        RouteMirror mirror = mock(RouteMirror.class);
        when(mirror.upsert(any(RouteRule.class))).thenReturn(Mono.empty());
        when(mirror.listIds()).thenReturn(Flux.error(new IllegalStateException("cassandra blip")));

        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader, true);

        Long mirrored = reconciler.runOnce().block();

        assertThat(mirrored).isEqualTo(1L);
        verify(mirror, never()).delete(any(String.class));
    }

    /** Non-leader → NEITHER upsert NOR prune: no repo read, no listIds, no delete. */
    @Test
    void runOnce_nonLeader_noUpsertNoPrune() {
        LeaderElection notLeader = new LeaderElection() {
            @Override public boolean isLeader() {
                return false;
            }

            @Override public String label() {
                return "test-non-leader";
            }
        };
        RouteMirror mirror = mock(RouteMirror.class);

        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, notLeader, true);

        Long mirrored = reconciler.runOnce().block();

        assertThat(mirrored).isEqualTo(0L);
        verify(repo, never()).list();
        verify(mirror, never()).upsert(any(RouteRule.class));
        verify(mirror, never()).listIds();
        verify(mirror, never()).delete(any(String.class));
    }

    /**
     * Prune-flag OFF → the upsert pass still runs but the orphan-prune is skipped entirely:
     * no {@code listIds()} read, no delete, even with a real orphan present.
     */
    @Test
    void runOnce_pruneFlagOff_noDelete() {
        RouteRule live = rule("id-live", "/api/admin/**");
        when(repo.list()).thenReturn(Flux.just(live));
        RouteMirror mirror = mock(RouteMirror.class);
        when(mirror.upsert(any(RouteRule.class))).thenReturn(Mono.empty());

        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader, false);

        Long mirrored = reconciler.runOnce().block();

        assertThat(mirrored).isEqualTo(1L);
        verify(mirror).upsert(live);
        verify(mirror, never()).listIds();
        verify(mirror, never()).delete(any(String.class));
    }

    /**
     * lastSuccessAt advances after a clean pass (upsert + guarded prune) via {@code runTick}.
     * Sanity that the success path (and thus the prune count log) completes normally.
     */
    @Test
    void runTick_advancesLastSuccessAfterPruneOnCleanPass() {
        RouteRule live = rule("id-live", "/api/admin/**");
        when(repo.list()).thenReturn(Flux.just(live));
        RouteMirror mirror = mock(RouteMirror.class);
        when(mirror.upsert(any(RouteRule.class))).thenReturn(Mono.empty());
        when(mirror.listIds()).thenReturn(Flux.just("id-live", "id-orphan"));
        when(mirror.delete(eq("id-orphan"))).thenReturn(Mono.empty());

        RouteMirrorReconciler reconciler = new RouteMirrorReconciler(repo, mirror, leader, true);
        assertThat(reconciler.lastSuccessAt()).isEqualTo(java.time.Instant.EPOCH);

        reconciler.runTick();

        // runTick subscribes synchronously here (all sources are in-memory), so success stamped.
        assertThat(reconciler.lastSuccessAt()).isAfter(java.time.Instant.EPOCH);
        verify(mirror).delete("id-orphan");
    }
}
