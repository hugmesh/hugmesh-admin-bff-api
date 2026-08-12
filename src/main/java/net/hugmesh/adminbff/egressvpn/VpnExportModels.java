package net.hugmesh.adminbff.egressvpn;

import java.util.List;

/**
 * The wire shapes of the signed PER-NODE egress-VPN export — CLONES
 * {@link net.hugmesh.adminbff.device.ExportModels} (the device-license-registry
 * export). The export is what the node-level reconcile agent compiles into the
 * {@code hugmesh-egress-vpn} OpenRC service's {@code active.conf} + the assigned
 * service set; the BFF never reconciles the node — it emits the compiled, signed set the
 * agent verifies against the BAKED key-USB public half and applies (or fail-closes,
 * keeping its last-good cache, on an unsigned/tampered/rolled-back payload).
 *
 * <p>The signature is DETACHED over the canonical body {@code {generation, node, entries}}
 * (a stable line-oriented UTF-8 encoding, NOT JSON). The body carries the
 * {@code secretRef} (so the agent fetches the actual {@code .conf} from its K8s Secret),
 * NEVER the private key — secrets stay off-DB / off-export.
 */
public final class VpnExportModels {

    private VpnExportModels() {
    }

    /**
     * One compiled egress assignment for the node: the config (by name + kind +
     * {@code secretRef}) and the public services that egress through it. The agent uses
     * {@code secretRef} to fetch the {@code .conf}/{@code .ovpn} from its K8s Secret, sniffs
     * {@code kind}, and marks the {@code serviceSlugs} pods with fwmark 0x76.
     *
     * @param configName   the operator-facing config name
     * @param kind         {@code wireguard} (first-class) / {@code openvpn} (fallback)
     * @param secretRef    the K8s Secret name carrying the config bytes (NEVER the key)
     * @param endpoint     the display endpoint (host:port) — provenance only
     * @param serviceSlugs the public services that egress via this config ({@code []} = ALL)
     */
    public record VpnEgressEntry(
            String configName,
            String kind,
            String secretRef,
            String endpoint,
            List<String> serviceSlugs) {
    }

    /**
     * The canonical (pre-signature) per-node export body. {@code generation} is the
     * monotonic counter ({@code max} over the contributing config + assignment rows) the
     * agent's rollback guard reads; {@code entries} are sorted deterministically so the
     * content-hash is stable.
     */
    public record VpnExportBody(
            String node,
            long generation,
            List<VpnEgressEntry> entries) {
    }

    /**
     * The signed envelope served by {@code GET /bff/admin/egress-vpn/export?node=}. Mirrors
     * {@code SignedExport}: {@code contentHash} is SHA-256(canonical-body-bytes);
     * {@code signature} is the detached Ed25519 over the canonical body bytes (base64), or
     * {@code null} when no signing key is configured (the agent fail-closes); {@code signed}
     * mirrors {@code signature != null}.
     */
    public record SignedVpnExport(
            VpnExportBody body,
            String contentHash,
            String signature,
            String publicKey,
            boolean signed) {
    }
}
