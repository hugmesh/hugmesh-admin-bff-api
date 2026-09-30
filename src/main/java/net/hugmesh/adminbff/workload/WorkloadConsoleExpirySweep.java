package net.hugmesh.adminbff.workload;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The scheduled WORKLOAD CONSOLE grant-expiry sweep — the single clock that returns a
 * granted admin to dark when their TTL lease elapses (DESIGN AXIOM 5 / DECISION 4). Mirrors
 * {@code SuspensionExpiryAction}: Lease-gated single-writer (only the leader replica runs
 * the tick), the per-row CAS {@code active -> expired} is the second guard so a second
 * replica/tick never double-acts, and the scan re-selects every overdue row on boot (survives
 * restarts). Cadence reuses the suspension-expiry interval defaults so no new cron knobs are
 * introduced.
 */
@Service
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class WorkloadConsoleExpirySweep {

    private static final Logger log = LoggerFactory.getLogger(WorkloadConsoleExpirySweep.class);

    private final WorkloadConsoleAdminService service;
    private final LeaderElection leader;
    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public WorkloadConsoleExpirySweep(WorkloadConsoleAdminService service, LeaderElection leader) {
        this.service = service;
        this.leader = leader;
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.workload-console.expiry.interval-ms:30000}",
            initialDelayString = "${app.workload-console.expiry.initial-delay-ms:20000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    public Mono<Void> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[workload-console-expiry] not leader ({}) — skipping tick", leader.label());
            return Mono.empty();
        }
        return service.sweepExpired().then()
                .onErrorResume(e -> {
                    log.warn("[workload-console-expiry] tick failed (will retry next tick): {}",
                            e.toString());
                    return Mono.empty();
                });
    }
}
