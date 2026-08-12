package net.hugmesh.adminbff.lease;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.integration.leader.event.AbstractLeaderEvent;
import org.springframework.integration.leader.event.OnGrantedEvent;
import org.springframework.integration.leader.event.OnRevokedEvent;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Kubernetes {@code Lease}-backed {@link LeaderElection} — the CHOSEN single-writer
 * primitive. spring-cloud-kubernetes fabric8 leader election runs a
 * {@code LeaderInitiator} that competes for a {@code Lease} (coordination.k8s.io) in
 * the pod's namespace and publishes Spring Integration {@link OnGrantedEvent} /
 * {@link OnRevokedEvent} when this replica gains/loses leadership for a configured
 * role. This listener tracks those events into a boolean the reconcile loop reads via
 * {@link #isLeader()}.
 *
 * <p>Only wired when {@code app.access-suspension.lease.enabled=true} AND the
 * spring-cloud-kubernetes leader machinery is active
 * ({@code spring.cloud.kubernetes.enabled=true} +
 * {@code spring.cloud.kubernetes.leader.enabled=true}, both OFF by default). Until a
 * grant event arrives the replica is conservatively NOT leader, so no two replicas
 * both write during election; a single-replica deployment leaves the Lease disabled
 * and uses {@link AlwaysLeader} instead.
 *
 * <p>The leader role name is scoped via {@code app.access-suspension.lease.role}
 * (default {@code access-suspension}) so an unrelated leader-election role in the
 * same pod could not flip this writer on/off.
 */
public class KubernetesLeaderElection
        implements LeaderElection, ApplicationListener<AbstractLeaderEvent> {

    private static final Logger log = LoggerFactory.getLogger(KubernetesLeaderElection.class);

    private final String role;
    private final AtomicBoolean leader = new AtomicBoolean(false);

    public KubernetesLeaderElection(String role) {
        this.role = role;
    }

    @Override
    public void onApplicationEvent(AbstractLeaderEvent event) {
        if (role != null && !role.equals(event.getRole())) {
            return; // a different leader-election role — not ours.
        }
        if (event instanceof OnGrantedEvent) {
            leader.set(true);
            log.info("[lease] leadership GRANTED for role '{}' — this replica is the access-suspension writer", role);
        } else if (event instanceof OnRevokedEvent) {
            leader.set(false);
            log.info("[lease] leadership REVOKED for role '{}' — this replica steps down", role);
        }
    }

    @Override
    public boolean isLeader() {
        return leader.get();
    }

    @Override
    public String label() {
        return "k8s-lease (role=" + role + ", leader=" + leader.get() + ")";
    }
}
