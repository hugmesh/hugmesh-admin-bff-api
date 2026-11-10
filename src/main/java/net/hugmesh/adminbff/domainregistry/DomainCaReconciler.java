package net.hugmesh.adminbff.domainregistry;

import net.hugmesh.adminbff.lease.LeaderElection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * The scheduled, leader-gated driver of {@link DomainCaEffector} (hugmesh-admin-bff-api#99).
 * Only wired when {@code app.domain-registry.ca.enabled=true}. Each tick works through the
 * pending {@code ca_ref = 'generate'} rows; a failed domain stays {@code ca_provisioned = false}
 * and is picked up again on the next tick, so an unavailable Vault delays the CA without
 * blocking domain setup (decision 87d = B). Only the leader replica calls Vault, so two
 * replicas never race to mint two roots for one domain.
 */
public class DomainCaReconciler {

    private static final Logger log = LoggerFactory.getLogger(DomainCaReconciler.class);

    private final DomainCaEffector effector;
    private final LeaderElection leader;

    public DomainCaReconciler(DomainCaEffector effector, LeaderElection leader) {
        this.effector = effector;
        this.leader = leader;
    }

    @Scheduled(
            fixedDelayString = "${app.domain-registry.ca.reconcile-interval-ms:60000}",
            initialDelayString = "${app.domain-registry.ca.reconcile-initial-delay-ms:45000}")
    public void runTick() {
        runOnce().onErrorResume(e -> Mono.empty()).subscribe();
    }

    /** One pass; empty when this replica is not the leader. Errors never escape a tick. */
    public Mono<List<DomainCaEffector.CaOutcome>> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[domain-ca] not leader ({}) — skipping tick", leader.label());
            return Mono.just(List.of());
        }
        return effector.provisionPending()
                .collectList()
                .onErrorResume(e -> {
                    log.warn("[domain-ca] reconcile pass failed (retry next tick): {}",
                            e.getClass().getSimpleName());
                    return Mono.just(List.of());
                });
    }
}
