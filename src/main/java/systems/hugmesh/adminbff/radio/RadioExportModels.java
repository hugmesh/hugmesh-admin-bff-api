package systems.hugmesh.adminbff.radio;

import java.util.List;

/**
 * The wire shapes of the signed PER-NODE node-radio export — REPRODUCES the
 * {@link systems.hugmesh.adminbff.storage.StorageExportModels} shapes EXACTLY (same
 * detached-Ed25519-over-canonical-body model, same monotonic-generation rollback guard,
 * same fail-closed empty body on an unknown fingerprint). The CONSUMER is the FUTURE
 * on-node meshbridge reconcile agent: it fetches its OWN node's export and learns ONLY the
 * radios attached to THIS node — never another node's / another domain's radios
 * (CONFIDENTIALITY: the agent bridges exactly what the control plane says belongs on THIS
 * node).
 *
 * <p>The signature is DETACHED over the canonical body {@code {generation, node_fp,
 * radios}} (see {@link SignedRadioExport}). The agent VERIFIES with the public half baked
 * in via the key-USB and FAILS CLOSED (keeps its last-good cache) on an unsigned /
 * tampered / rolled-back (generation &le; current) payload.
 */
public final class RadioExportModels {

    private RadioExportModels() {}

    /**
     * One ACTIVE radio attached to the node. The meshbridge agent opens the transport this
     * entry describes: {@code serial} — the node-local {@code serialPath};
     * {@code tcp} — the Meshtastic TCP API at {@code host:port} (default 4403);
     * {@code mqtt} — the Meshtastic MQTT broker at {@code host:port} (default 1883), JSON
     * integration under {@code topicRoot} on {@code channelName}, downlinks attributed to
     * the optional {@code gatewayNodeId}. {@code meshChannel} is the Meshtastic channel
     * index (0..7) the bridge binds; {@code radioId} keys the bridge's channel map.
     */
    public record RadioEntry(
            String radioId,
            String transport,
            String serialPath,
            String host,
            Integer port,
            String topicRoot,
            String channelName,
            String gatewayNodeId,
            int meshChannel) {
    }

    /**
     * The canonical (pre-signature) export body for ONE node — the deterministic content the
     * detached signature covers. {@code nodeFp} is the node's stable machine-key fingerprint;
     * {@code generation} is {@code max(generation)} across the node's radios (the agent's
     * rollback guard reads it); ENTRIES are sorted deterministically so the
     * {@code content-hash} is stable.
     */
    public record RadioExportBody(
            String nodeFp,
            long generation,
            List<RadioEntry> radios) {
    }

    /**
     * The signed envelope served by {@code GET .../export?node=}. {@code body} is the
     * {@link RadioExportBody}; {@code contentHash} is SHA-256(canonical-body-bytes);
     * {@code signature} is the detached Ed25519 signature over the canonical body bytes
     * (base64), or {@code null} when no signing key is configured (the consumer fail-closes);
     * {@code publicKey} advertises the verifying half (base64 X.509) when configured.
     * {@code signed} mirrors {@code signature != null}.
     */
    public record SignedRadioExport(
            RadioExportBody body,
            String contentHash,
            String signature,
            String publicKey,
            boolean signed) {
    }
}
