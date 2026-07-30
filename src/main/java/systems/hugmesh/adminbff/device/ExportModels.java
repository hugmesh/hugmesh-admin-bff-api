package systems.hugmesh.adminbff.device;

import java.util.List;

/**
 * The wire shapes of the signed per-mesh device-registry export [FIX-SIGNCACHE]. The
 * export is what BOTH enforcement layers compile from (the per-node sshd
 * {@code AuthorizedKeysCommand} and the headscale policy generator), so the BFF never
 * evaluates SSH authorization at connect time — it only emits the compiled, signed set.
 *
 * <p>The signature is DETACHED over the canonical body {@code {generation, mesh_id,
 * content-hash, body}} (see {@link SignedExport}). A node VERIFIES with the public half
 * baked in via the key-USB and FAILS CLOSED (keeps its last-good cache) on an unsigned /
 * tampered / rolled-back (generation &le; current) payload.
 */
public final class ExportModels {

    private ExportModels() {}

    /**
     * One compiled authorized-operator entry per (operator x reachable-node) the AUTH
     * PREDICATE permits, pinned to the exact key fingerprints [FIX-PINKEY] the operator
     * may present. Layer B turns each entry into the {@code AuthorizedKeysCommand} lines
     * for {@code machineKeyFp} (only keys whose offered {@code %f} matches a pinned
     * fingerprint are emitted); Layer A turns it into a permitted headscale SSH edge.
     *
     * @param operator        the Casdoor subject permitted to SSH
     * @param machineKeyFp    the node's stable headscale machine-key fingerprint
     * @param hostname        the node's hostname (for the operator-facing audit line)
     * @param keyFingerprints the EXACT pinned SSH pubkey fingerprints the operator may
     *                        present on this node (FIX-PINKEY)
     * @param via             how the grant was earned ({@code DEVICE-LICENSE} /
     *                        {@code DOMAIN-LICENSE}) — PROVENANCE ONLY, never a role
     *                        assertion (the enforcement layers (e) independently re-derive
     *                        the operator's role from the validated issuer)
     */
    public record AuthorizedOperator(
            String operator,
            String machineKeyFp,
            String hostname,
            List<String> keyFingerprints,
            String via) {

        // POST-VERIFY CORRECTION (2026-06-12): the export carries ONLY explicit ADMIN
        // licenses. The former VIA_SUPERADMIN_MESH provenance is REMOVED — the unscoped
        // signed export cannot see operator roles, so it must NEVER assert SUPERADMIN
        // access. SUPERADMIN mesh-reach is a deferred Layer-A headscale concern, not a
        // value this export can carry.
        public static final String VIA_DEVICE_LICENSE = "DEVICE-LICENSE";
        public static final String VIA_DOMAIN_LICENSE = "DOMAIN-LICENSE";
    }

    /**
     * The canonical (pre-signature) export body for one mesh — the deterministic content
     * the detached signature covers. {@code generation} is the monotonic counter
     * ({@code max(license.generation)}) the node's rollback guard reads; ENTRIES are
     * sorted deterministically so the {@code content-hash} is stable.
     */
    public record ExportBody(
            String meshId,
            long generation,
            List<AuthorizedOperator> operators) {
    }

    /**
     * The signed envelope served by {@code GET /export}. {@code body} is the
     * {@link ExportBody}; {@code contentHash} is SHA-256(canonical-body-bytes);
     * {@code signature} is the detached Ed25519 signature over the canonical body bytes
     * (base64), or {@code null} when no signing key is configured (the consumer fail-closes
     * and keeps its last-good cache); {@code publicKey} advertises the verifying half
     * (base64 X.509) when the deployment configured one. {@code signed} is a convenience
     * flag mirroring {@code signature != null}.
     */
    public record SignedExport(
            ExportBody body,
            String contentHash,
            String signature,
            String publicKey,
            boolean signed) {
    }
}
