package net.hugmesh.adminbff.golive;

import java.util.List;

/**
 * The wire shapes of the signed {@code go_live_intent} export — CLONES
 * {@link net.hugmesh.adminbff.domainregistry.DomainExportModels} (and, through it, the
 * device-license / egress-VPN export models). The export is what the HOST-SIDE go-live agent
 * consumes: it verifies the detached Ed25519 signature against the key-USB-baked public half,
 * applies its strict-monotonic rollback guard, and ONLY THEN writes the host's
 * {@code /etc/hugmesh/go-live} marker (or removes it when the intent is roll-back /
 * absent). The in-cluster BFF ships INTENT ONLY over this channel — per the pinned contract
 * it never writes (or claims to have written) the marker itself.
 *
 * <h3>Cross-domain by construction</h3>
 * Like the domain-registry export, go-live intents are cross-domain SUPERADMIN infra: there
 * is nothing per-node to scope, so the body carries EVERY RECORDED intent and the optional
 * {@code node} fingerprint is pinned into the header as PROVENANCE only.
 *
 * <h3>Withdraw = absence, still forward</h3>
 * A withdrawn intent leaves the body (absence = nothing to apply), but its CAS bumped the
 * table-wide monotonic {@code generation} the export carries (max over ALL rows, including
 * withdrawn), so the agent's strict-monotonic guard ACCEPTS the removal instead of treating
 * the smaller body as a stale replay.
 *
 * <p>The signature is DETACHED over a canonical line-oriented UTF-8 encoding (NOT JSON — no
 * serializer field-ordering ambiguity). NO SECRETS ride the body: {@code provider} is a
 * catalog key; tokens live in keys-USB/Vault, never here.
 */
public final class GoLiveExportModels {

    private GoLiveExportModels() {
    }

    /**
     * One compiled entry per RECORDED intent — everything the host agent needs to converge
     * the marker for one brand.
     *
     * @param clusterDomain the brand's base domain the intent targets
     * @param targetState   {@code public} (write the go-live marker) | {@code internal}
     *                      (remove it / stay internal) — the host RELEASE_STATE vocabulary
     * @param exposureModel the wizard's chosen exposure model (may be empty for roll-back)
     * @param provider      the {@link GoLiveProviderCatalog} key (may be empty for roll-back)
     * @param requestedBy   the recording SUPERADMIN's subject (audit provenance)
     * @param intentId      the backing {@code go_live_intent} row id (the ack correlation key
     *                      the agent writes back through {@code applied_at}/{@code applied_by})
     * @param generation    the row's monotonic generation stamp
     */
    public record GoLiveIntentEntry(
            String clusterDomain,
            String targetState,
            String exposureModel,
            String provider,
            String requestedBy,
            String intentId,
            long generation) {
    }

    /**
     * The canonical (pre-signature) export body. {@code generation} is the EXPORT-level
     * monotonic counter — {@code max(generation)} over ALL rows (withdrawn included, so a
     * withdraw still advances it) — the agent's strict-monotonic rollback guard reads;
     * {@code node} is the addressing fingerprint pinned as PROVENANCE; {@code entries} are
     * sorted deterministically by {@code clusterDomain} so the content-hash is reproducible.
     */
    public record GoLiveExportBody(
            String node,
            long generation,
            List<GoLiveIntentEntry> entries) {
    }

    /**
     * The signed envelope served by {@code GET /bff/admin/go-live/export}. Mirrors
     * {@code SignedDomainExport}: {@code contentHash} is SHA-256(canonical-body-bytes);
     * {@code signature} is the detached Ed25519 over the canonical body bytes (base64), or
     * {@code null} when no signing key is configured (the agent fail-closes and keeps its
     * last-good cache — it NEVER applies an unsigned intent); {@code publicKey} advertises
     * the verifying half (base64 X.509); {@code signed} mirrors {@code signature != null}.
     */
    public record SignedGoLiveExport(
            GoLiveExportBody body,
            String contentHash,
            String signature,
            String publicKey,
            boolean signed) {
    }
}
