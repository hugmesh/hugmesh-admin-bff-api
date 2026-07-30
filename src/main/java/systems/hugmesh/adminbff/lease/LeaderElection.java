package systems.hugmesh.adminbff.lease;

/**
 * Single-writer guard for the access_suspension reconcile + expiry loop. admin-bff
 * may run more than one replica, and the loop is the ONLY caller of
 * {@code CasdoorAdminClient.add/removeUserFromRole} + the homeserver suspend seam, so
 * exactly one replica must own a tick at a time. Every loop tick checks
 * {@link #isLeader()} and skips when it is not the leader.
 *
 * <p>The CHOSEN production primitive is a Kubernetes {@code Lease}
 * (coordination.k8s.io) via spring-cloud-kubernetes fabric8 leader election — see
 * {@link KubernetesLeaderElection}. When the k8s leader machinery is disabled (a
 * single replica, or a cluster-less dev/test/CI run), {@link AlwaysLeader} makes the
 * loop unconditionally the writer. The choice is config-only
 * ({@code app.access-suspension.lease.enabled}) so flipping the Lease on later
 * requires no code change.
 */
public interface LeaderElection {

    /** True iff THIS replica currently holds leadership and may write. */
    boolean isLeader();

    /** A short human label for logs (which primitive is in force). */
    String label();
}
