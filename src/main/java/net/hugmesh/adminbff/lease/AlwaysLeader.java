package net.hugmesh.adminbff.lease;

/**
 * The default {@link LeaderElection}: this replica is ALWAYS the writer. Used when
 * the k8s Lease primitive is disabled
 * ({@code app.access-suspension.lease.enabled=false}, the default) — i.e. a single
 * admin-bff replica or a cluster-less dev/test/CI run, where there is no second
 * writer to coordinate against. In-cluster multi-replica deployments flip the Lease
 * on and get {@link KubernetesLeaderElection} instead.
 */
public class AlwaysLeader implements LeaderElection {

    @Override
    public boolean isLeader() {
        return true;
    }

    @Override
    public String label() {
        return "always-leader (single-writer lease disabled)";
    }
}
