package systems.hugmesh.adminbff.routeaccess;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import systems.hugmesh.adminbff.lease.LeaderElection;

/**
 * Wires the {@link RouteMirrorReconciler} self-healing sweep, gated behind the SAME flag
 * as the mirror itself, {@code app.mirror.cassandra.enabled} (DEFAULT true). Mirrors
 * {@code BackupStatusReconcilerConfig} EXACTLY (the {@code @ConditionalOnProperty} idiom +
 * the shared {@link LeaderElection} single-writer bean).
 *
 * <h3>Off together with the mirror</h3>
 * With {@code app.mirror.cassandra.enabled=false} NEITHER the per-write mirror NOR this
 * reconciler has anything to do, so the bean is ABSENT and no {@code @Scheduled} sweep
 * exists. With the mirror ON (the default) the reconciler is registered; if Cassandra is
 * merely unreachable it stays harmless because every {@link RouteMirror#upsert} the loop
 * drives is best-effort (a logged no-op on failure) — exactly the path the per-write
 * mirror uses.
 *
 * <h3>Single-writer</h3>
 * Injects the platform-wide {@link LeaderElection} bean ({@code AlwaysLeader} by default;
 * the k8s {@code Lease} when {@code app.access-suspension.lease.enabled=true}) — the SAME
 * single-writer primitive the suspension + games + cloud-backup reconcile loops use, so at
 * most one replica re-mirrors at a time. (The re-upsert is value-idempotent — same id →
 * same row — so a double-sweep is harmless even without the Lease.)
 *
 * <h3>G4 — guarded delete-reconcile (orphan prune)</h3>
 * Passes {@code app.mirror.cassandra.reconcile.prune-orphans} (DEFAULT true) into the
 * reconciler to gate the orphan-prune pass that closes the delete-side over-grant gap. The
 * empty/failed-read guard in {@link RouteMirrorReconciler} applies REGARDLESS of the flag —
 * the flag only turns the prune pass on/off, never the safety guard.
 */
@Configuration(proxyBeanMethods = false)
public class RouteMirrorReconcilerConfig {

    private static final Logger log = LoggerFactory.getLogger(RouteMirrorReconcilerConfig.class);

    @Bean
    @ConditionalOnProperty(name = "app.mirror.cassandra.enabled", havingValue = "true",
            matchIfMissing = true)
    RouteMirrorReconciler routeMirrorReconciler(
            RouteAccessRepository repo, RouteMirror mirror, LeaderElection leader,
            @Value("${app.mirror.cassandra.reconcile.prune-orphans:true}") boolean pruneOrphans) {
        log.info("[route-mirror-reconciler] self-healing route-mirror sweep ENABLED "
                + "(single-writer via {}, orphan-prune={})", leader.label(), pruneOrphans);
        return new RouteMirrorReconciler(repo, mirror, leader, pruneOrphans);
    }
}
