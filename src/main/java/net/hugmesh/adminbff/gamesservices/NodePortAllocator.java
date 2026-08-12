package net.hugmesh.adminbff.gamesservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.HashSet;
import java.util.Set;

/**
 * Allocates a raw-L4 NodePort for a game instance from a RESERVED sub-pool of the k8s
 * NodePort range. Game protocols (UDP/TCP) are L4 and cannot traverse Spring Cloud Gateway
 * (an L7 proxy), so each instance exposing a game protocol gets a per-instance NodePort;
 * HTTP consoles go via be-gateway path-routing instead (no NodePort).
 *
 * <p><b>Reserved sub-pool, not the whole 30000-32767 range.</b> The default pool is a small
 * carve-out ({@code games-services.nodeport.pool-start}..{@code pool-end}, default
 * 31000-31099) so game instances cannot exhaust the ports other services may NodePort. The
 * in-use set is every node_port held by a NON-TERMINAL instance (cluster-wide: the range is
 * a single L4 resource shared across brands), so a terminated instance frees its port.
 *
 * <p><b>Fail-closed on exhaustion.</b> When every port in the pool is taken,
 * {@link #allocate} errors — the caller surfaces a clean 409/503 rather than silently
 * reusing a live port. The allocation is only persisted via the repo's
 * {@code assignPortAndConsole} CAS (node_port IS NULL guard), so two concurrent allocators
 * (multi-replica) can compute the same candidate but only one write wins; the loser retries.
 *
 * <p>This computes the candidate from the DB-observed in-use set (single source of truth) —
 * it does NOT reserve in memory, so it is stateless + restart-safe. The Lease-gated
 * reconciler is the single caller in practice, so contention is rare.
 */
@Component
public class NodePortAllocator {

    private static final Logger log = LoggerFactory.getLogger(NodePortAllocator.class);

    private final GameInstanceRepository repo;
    private final int poolStart;
    private final int poolEnd;

    public NodePortAllocator(GameInstanceRepository repo,
                             @Value("${games-services.nodeport.pool-start:31000}") int poolStart,
                             @Value("${games-services.nodeport.pool-end:31099}") int poolEnd) {
        this.repo = repo;
        this.poolStart = poolStart;
        this.poolEnd = poolEnd;
    }

    public int poolStart() { return poolStart; }
    public int poolEnd() { return poolEnd; }

    /**
     * The lowest free NodePort in the reserved pool, or an error if the pool is exhausted.
     * Pure computation over the DB-observed in-use set; persistence is the caller's CAS.
     */
    public Mono<Integer> allocate() {
        // Collect all in-use ports then find the lowest free slot in the pool.
        return repo.allocatedNodePorts().collectList().map(this::findFreePort);
    }

    /** Return the lowest free port in the pool, or throw if exhausted. */
    private Integer findFreePort(java.util.List<Integer> used) {
        Set<Integer> taken = new HashSet<>(used);
        for (int p = poolStart; p <= poolEnd; p++) {
            if (!taken.contains(p)) {
                return p;
            }
        }
        log.warn("[games-nodeport] reserved pool {}-{} EXHAUSTED ({} in use)",
                poolStart, poolEnd, taken.size());
        throw new NodePortExhaustedException(poolStart, poolEnd);
    }

    /** Thrown when the reserved NodePort pool has no free port. */
    public static final class NodePortExhaustedException extends RuntimeException {
        public NodePortExhaustedException(int start, int end) {
            super("games-services NodePort pool " + start + "-" + end + " is exhausted");
        }
    }
}
