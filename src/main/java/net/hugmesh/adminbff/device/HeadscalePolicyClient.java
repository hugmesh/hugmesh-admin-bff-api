package net.hugmesh.adminbff.device;

import reactor.core.publisher.Mono;

/**
 * The WRITE seam into the headscale control plane's POLICY API — the Layer-A counterpart to
 * the READ-ONLY {@link HeadscaleNodesClient}. It mirrors the {@code InstanceConfigMapWriter} /
 * {@code BackupEffector} dark-effector precedent in this repo: an interface with a real
 * {@link WebClientHeadscalePolicyClient} impl (gated {@code app.registry.headscale-acl.enabled=true})
 * and a {@link NoopHeadscalePolicyClient} cluster-less default, so the reconcile loop is fully
 * exercisable with NO live headscale.
 *
 * <p>Two operations against headscale's gRPC-gateway REST surface (Bearer API key):
 * <ul>
 *   <li>{@link #getPolicy()} — {@code GET /api/v1/policy}, returns the currently-stored policy
 *       text (so the reconciler can skip a no-op PUT — idempotency); empty when headscale has
 *       no policy yet or the deployment runs in file-policy mode;</li>
 *   <li>{@link #setPolicy(String)} — {@code PUT /api/v1/policy} with body
 *       {@code {"policy": "<hujson>"}}, uploads + applies a new ACL policy (headscale only
 *       accepts this in DB policy mode).</li>
 * </ul>
 * Neither HARD-FAILS: a degraded call resolves to a {@link PushOutcome#degraded} so the
 * reconcile loop keeps its last-good compiled text and retries next tick (fail-closed — a
 * rejected/unreachable headscale NEVER widens or clears the live mesh policy).
 */
public interface HeadscalePolicyClient {

    /**
     * The currently-stored headscale ACL policy text, or {@link Mono#empty()} when headscale
     * has none / is unreachable / this is the Noop client. NEVER errors — an unreachable
     * control plane resolves to empty so the reconciler treats "unknown current" as "must
     * attempt a push" rather than crashing the tick.
     */
    Mono<String> getPolicy();

    /**
     * Upload + apply {@code policyJson} as the headscale ACL policy ({@code PUT /api/v1/policy}).
     * Returns a {@link PushOutcome}: {@link PushOutcome#applied} on a 2xx, {@link PushOutcome#stubbed}
     * when this is the Noop client (disabled), {@link PushOutcome#degraded} on any non-2xx /
     * transport error (the loop keeps last-good + retries). NEVER throws.
     */
    Mono<PushOutcome> setPolicy(String policyJson);

    /** True only for the real, wired-to-headscale client (the runtime seam signal). */
    boolean isReal();

    /**
     * The outcome of a policy push. {@code applied} = headscale accepted the PUT;
     * {@code stubbed} = disabled/Noop (no HTTP issued); {@code degraded} = a real push that
     * failed (non-2xx / transport) — the loop keeps last-good. {@code detail} is a short,
     * NON-SECRET diagnostic for logs (never the policy body, never the API key).
     */
    record PushOutcome(Status status, String detail) {

        public enum Status { APPLIED, STUBBED, DEGRADED }

        public static PushOutcome applied() { return new PushOutcome(Status.APPLIED, null); }
        public static PushOutcome stubbed() { return new PushOutcome(Status.STUBBED, null); }
        public static PushOutcome degraded(String detail) { return new PushOutcome(Status.DEGRADED, detail); }

        public boolean isApplied()  { return status == Status.APPLIED; }
        public boolean isStubbed()  { return status == Status.STUBBED; }
        public boolean isDegraded() { return status == Status.DEGRADED; }
    }
}
