package net.hugmesh.adminbff.suspension;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Thin facade the endpoints use to TRIGGER a reconcile tick after writing /
 * clearing an access_suspension row, without coupling the controllers to the
 * individual platform actions. It fans a one-shot tick across the matrix + mastodon
 * + mesh reconcilers and the expiry action.
 *
 * <p>This is the "endpoints only write the table + trigger a tick" half of the
 * single-writer contract: the trigger is best-effort and additive to the
 * {@code @Scheduled} sweeps (which are the real backstop), and every action is
 * itself leader-gated + breaker-wrapped, so a manual trigger never bypasses the
 * single-writer invariant.
 */
@Service
public class AccessSyncActions {

    private final MatrixAccessSyncAction matrix;
    private final MastodonAccessSyncAction mastodon;
    /** The ROLE_MESH reconciler. Casdoor-only (no homeserver leg) — see
     *  {@link MeshAccessSyncAction} — but it is dispatched here exactly like its two
     *  siblings, so a mesh ban/lift converges on the endpoint's own tick rather than
     *  waiting for the next @Scheduled sweep. */
    private final MeshAccessSyncAction mesh;
    private final SuspensionExpiryAction expiry;

    public AccessSyncActions(MatrixAccessSyncAction matrix,
                             MastodonAccessSyncAction mastodon,
                             MeshAccessSyncAction mesh,
                             SuspensionExpiryAction expiry) {
        this.matrix = matrix;
        this.mastodon = mastodon;
        this.mesh = mesh;
        this.expiry = expiry;
    }

    /**
     * Run one reconcile + expiry pass now (best-effort). Errors are swallowed by the
     * underlying actions; this never fails the caller's write.
     */
    public Mono<Void> triggerTick() {
        return matrix.runOnce()
                .then(mastodon.runOnce())
                .then(mesh.runOnce())
                .then(expiry.runOnce())
                .onErrorResume(e -> Mono.empty());
    }
}
