package net.hugmesh.adminbff.egressvpn;

import reactor.core.publisher.Mono;

/**
 * The POD-LABELING leg of the egress-VPN control plane — the seam that stamps the OPT-IN
 * label <b>{@code snapdragon.systems/vpn-egress=true}</b> (the key the generator's
 * {@code egress-vpn-interaction.yaml} NetworkPolicy selects on, published as
 * {@code vpnEgressLabel} in its {@code optional-services.yaml} entry) onto the workloads named
 * by the ACTIVE assignments — and removes it when an assignment is revoked. Without this leg
 * the interaction NetworkPolicy is inert (it matches nothing) and an assigned service never
 * gains the direct-egress allow the node split-tunnel captures.
 *
 * <h3>What gets labelled (the generator's PR5 model)</h3>
 * Per the {@code egress-vpn-interaction.yaml} header: an assignment carrying a
 * {@code serviceSlug} marks JUST that service; an all-services (null-slug) assignment marks
 * the configured public set (v1: akkoma / tuwunel / coturn). Labels land on the resolved
 * Deployments/StatefulSets ({@code metadata.labels}, a restart-free marker — deliberately NOT
 * {@code spec.template}, which would roll every pod on each assignment) AND on their LIVE pods
 * (selected by the workload's {@code matchLabels}), because the NetworkPolicy selects PODS.
 *
 * <h3>Reconcile-shaped, fail-closed</h3>
 * {@link #reconcile()} converges the WHOLE label state from the active-assignment set (adds
 * AND removes), so the same call serves the on-mutation fast path and the scheduled drift
 * sweep ({@link VpnEgressLabelReconciler}) — a pod replaced between ticks is re-labelled
 * within one cadence; until then it is merely default-denied back onto the Squid-proxy path
 * (fail-closed, never a leak). Implementations swallow cluster errors (a labeling failure
 * must never fail the admin mutation that triggered it).
 */
public interface VpnEgressLabeler {

    /** The pod opt-in label key the interaction NetworkPolicy selects on. */
    String LABEL_KEY = "snapdragon.systems/vpn-egress";

    /** The only value the NetworkPolicy matches. Un-labeling REMOVES the key (never "false"). */
    String LABEL_VALUE = "true";

    /**
     * Converge workload + pod labels to the current ACTIVE assignment set. Returns the number
     * of objects actually changed (0 for the dark Noop or a swallowed failure). Never errors.
     */
    Mono<Long> reconcile();

    /** {@code true} only for the real cluster-dialing labeler (the wiring tests' probe). */
    boolean isReal();
}
