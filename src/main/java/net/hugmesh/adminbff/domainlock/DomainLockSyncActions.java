package net.hugmesh.adminbff.domainlock;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Thin facade the {@link DomainLockService} uses to TRIGGER a reconcile tick after
 * writing / clearing a domain_lock row, without coupling the service to the individual
 * platform actions. It fans a one-shot tick across the matrix + mastodon domain-lock
 * reconcilers — the ADD-active analogue of
 * {@link net.hugmesh.adminbff.suspension.AccessSyncActions}.
 *
 * <p>This is the "endpoints only write the table + trigger a tick" half of the
 * single-writer contract: the trigger is best-effort and additive to the
 * {@code @Scheduled} sweeps (which are the real backstop), and every action is itself
 * leader-gated + breaker-wrapped, so a manual trigger never bypasses the single-writer
 * invariant.
 */
@Service
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class DomainLockSyncActions {

    private final MatrixDomainLockSyncAction matrix;
    private final MastodonDomainLockSyncAction mastodon;

    public DomainLockSyncActions(MatrixDomainLockSyncAction matrix,
                                 MastodonDomainLockSyncAction mastodon) {
        this.matrix = matrix;
        this.mastodon = mastodon;
    }

    /**
     * Run one reconcile pass now across both platform domain-lock reconcilers
     * (best-effort). Errors are swallowed by the underlying actions; this never fails
     * the caller's write.
     */
    public Mono<Void> triggerTick() {
        return matrix.runOnce()
                .then(mastodon.runOnce())
                .onErrorResume(e -> Mono.empty());
    }
}
