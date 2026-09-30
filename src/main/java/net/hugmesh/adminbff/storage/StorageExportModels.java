package net.hugmesh.adminbff.storage;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The wire shapes of the signed PER-NODE node-storage export — REPRODUCES the
 * {@link net.hugmesh.adminbff.device.ExportModels} shapes EXACTLY (same
 * detached-Ed25519-over-canonical-body model, same monotonic-generation rollback guard,
 * same fail-closed empty body on an unknown fingerprint). A node fetches its OWN export and
 * learns ONLY its own pools + their active assignments — never another node's / another
 * domain's storage (CONFIDENTIALITY: the node reconciler provisions exactly what the
 * control plane says belongs on THIS node).
 *
 * <p>The signature is DETACHED over the canonical body {@code {generation, node_fp, pools}}
 * (see {@link SignedStorageExport}). A node VERIFIES with the public half baked in via the
 * key-USB and FAILS CLOSED (keeps its last-good cache) on an unsigned / tampered /
 * rolled-back (generation &le; current) payload.
 */
public final class StorageExportModels {

    private StorageExportModels() {}

    /** One active service placed on a pool — the node turns each into a node-pinned PV bind
     *  for {@code pvcName} sized {@code requestedBytes}. */
    public record AssignmentEntry(
            String serviceName,
            String pvcName,
            long requestedBytes) {
    }

    /**
     * One ACTIVE pool pinned to the node, with its active assignments. The node reconciler
     * (PR6) provisions {@code poolPath} (reusing {@code provision_storage --pool}), patches
     * the local-path-provisioner {@code nodePathMap}, and binds each assignment's PV.
     */
    public record PoolEntry(
            String poolId,
            String diskSerial,
            String poolPath,
            long reservedBytes,
            boolean isExclusive,
            String filesystem,
            List<AssignmentEntry> assignments) {

        public PoolEntry {
            assignments = assignments == null ? null : Collections.unmodifiableList(new ArrayList<>(assignments));
        }
    }

    /**
     * The canonical (pre-signature) export body for ONE node — the deterministic content the
     * detached signature covers. {@code nodeFp} is the node's stable machine-key fingerprint;
     * {@code generation} is {@code max(generation)} across the node's pools + assignments
     * (the node's rollback guard reads it); ENTRIES are sorted deterministically so the
     * {@code content-hash} is stable.
     */
    public record StorageExportBody(
            String nodeFp,
            long generation,
            List<PoolEntry> pools) {

        public StorageExportBody {
            pools = pools == null ? null : Collections.unmodifiableList(new ArrayList<>(pools));
        }
    }

    /**
     * The signed envelope served by {@code GET .../export?node=}. {@code body} is the
     * {@link StorageExportBody}; {@code contentHash} is SHA-256(canonical-body-bytes);
     * {@code signature} is the detached Ed25519 signature over the canonical body bytes
     * (base64), or {@code null} when no signing key is configured (the consumer fail-closes);
     * {@code publicKey} advertises the verifying half (base64 X.509) when configured.
     * {@code signed} mirrors {@code signature != null}.
     */
    public record SignedStorageExport(
            StorageExportBody body,
            String contentHash,
            String signature,
            String publicKey,
            boolean signed) {
    }
}
