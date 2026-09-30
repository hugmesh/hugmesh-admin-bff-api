package net.hugmesh.adminbff.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.RegistrySigner;
import net.hugmesh.adminbff.storage.StorageExportModels.AssignmentEntry;
import net.hugmesh.adminbff.storage.StorageExportModels.PoolEntry;
import net.hugmesh.adminbff.storage.StorageExportModels.SignedStorageExport;
import net.hugmesh.adminbff.storage.StorageExportModels.StorageExportBody;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Builds the SIGNED PER-NODE node-storage export — REPRODUCES
 * {@link net.hugmesh.adminbff.device.DeviceRegistryExportService#exportNode} EXACTLY:
 * the same {@code machine_key_fp -> node} resolution (UNSCOPED, fail-closed on an unknown
 * fingerprint), the same canonical-bytes header, the same detached Ed25519 signature (reusing
 * {@link RegistrySigner}), and the same monotonic {@code generation} a node's rollback guard
 * reads. A Layer-B node fetches its OWN export and learns ONLY its own pools + their active
 * assignments — never another node's / another domain's storage [CONFIDENTIALITY].
 *
 * <h3>FAIL-CLOSED on an unknown fingerprint</h3>
 * An UNKNOWN fp yields an EMPTY (but signed) body over an empty node header — NOT an error,
 * so a probe of an unknown fp leaks NOTHING (no pool count, no node id, no service name).
 * The pools repo is NEVER even read for an unknown node (no over-fetch), exactly as the
 * device export's per-node path does.
 */
@Service
public class NodeStorageExportService {

    private static final Logger log = LoggerFactory.getLogger(NodeStorageExportService.class);

    private final DeviceRegistryRepository devices;
    private final StoragePoolRepository pools;
    private final ServiceAssignmentRepository assignments;
    private final RegistrySigner signer;

    public NodeStorageExportService(DeviceRegistryRepository devices, StoragePoolRepository pools,
                                    ServiceAssignmentRepository assignments, RegistrySigner signer) {
        this.devices = devices;
        this.pools = pools;
        this.assignments = assignments;
        this.signer = signer;
    }

    /**
     * Build + sign the PER-NODE export for ONE device, addressed by its stable
     * {@code machine_key_fp}. The signed body carries ONLY the ACTIVE pools pinned to THAT
     * node, each with its ACTIVE assignments. UNSCOPED resolution + FAIL-CLOSED: an unknown
     * fp yields an empty signed body, never a leaky error.
     */
    public Mono<SignedStorageExport> exportNode(String machineKeyFp) {
        return devices.findByMachineKey(machineKeyFp)
                .flatMap(node -> pools.listActiveForDevice(node.id()).collectList()
                        .flatMap(poolRows -> Flux.fromIterable(poolRows)
                                .flatMap(this::resolvePool)   // each pool -> (entry, gen) (UNSCOPED)
                                .collectList()
                                .map(resolved -> sign(compile(node, poolRows, resolved)))))
                // fail-closed: unknown fp -> empty signed body over an empty node header.
                .switchIfEmpty(Mono.fromSupplier(() -> sign(emptyBody())));
    }

    /** A pool entry plus the max generation seen across the pool + its assignments. */
    private record ResolvedPool(PoolEntry entry, long maxGeneration) {}

    /** Resolve one pool's ACTIVE assignments into a {@link PoolEntry} and the max generation
     *  across the pool and those assignments (UNSCOPED — the export is the node's own truth). */
    private Mono<ResolvedPool> resolvePool(StoragePool pool) {
        // Collect active assignments then build the PoolEntry and max-generation summary.
        return assignments.listActiveForPool(pool.id()).collectList()
                .map(rows -> buildResolvedPool(pool, rows));
    }

    /** Build a ResolvedPool from the pool row and its active assignments. */
    private static ResolvedPool buildResolvedPool(StoragePool pool, java.util.List<ServiceAssignment> rows) {
        long maxGen = pool.generation();
        List<AssignmentEntry> as = new ArrayList<>(rows.size());
        for (ServiceAssignment a : rows) {
            maxGen = Math.max(maxGen, a.generation());
            as.add(new AssignmentEntry(a.serviceName(), a.pvcName(), a.requestedBytes()));
        }
        PoolEntry entry = new PoolEntry(pool.id(), pool.diskSerial(), pool.poolPath(),
                pool.reservedBytes(), pool.isExclusive(), pool.filesystem(), as);
        return new ResolvedPool(entry, maxGen);
    }

    /**
     * Compile the per-node body deterministically (stable pool/assignment ordering) so the
     * content-hash + signature are reproducible. {@code generation} is the MAX across the
     * node's pools and assignments — a node accepts ONLY a strictly-higher generation than
     * its last-good cache (rollback guard). Pure + deterministic (no IO).
     */
    @SuppressWarnings("PMD.UnusedFormalParameter")
    private StorageExportBody compile(Device node, List<StoragePool> poolRows,
                                      List<ResolvedPool> resolved) {
        long maxGen = 0L;
        List<PoolEntry> entries = new ArrayList<>(resolved.size());
        for (ResolvedPool r : resolved) {
            maxGen = Math.max(maxGen, r.maxGeneration());
            PoolEntry e = r.entry();
            List<AssignmentEntry> sorted = new ArrayList<>(e.assignments());
            sorted.sort(Comparator.comparing(AssignmentEntry::serviceName));
            entries.add(new PoolEntry(e.poolId(), e.diskSerial(), e.poolPath(), e.reservedBytes(),
                    e.isExclusive(), e.filesystem(), sorted));
        }
        entries.sort(Comparator.comparing(PoolEntry::poolId));
        return new StorageExportBody(node.machineKeyFp(), maxGen, List.copyOf(entries));
    }

    /** The empty (unknown-fp) body — empty node header, no pools (fail-closed). */
    private static StorageExportBody emptyBody() {
        return new StorageExportBody("", 0L, List.of());
    }

    /** Wrap a compiled body in the signed envelope: SHA-256 content-hash + detached Ed25519
     *  over the canonical body bytes. Unsigned when no key (consumer fail-closes). */
    SignedStorageExport sign(StorageExportBody body) {
        byte[] canonical = canonicalBytes(body);
        String hash = RegistrySigner.contentHash(canonical);
        String sig = signer.sign(canonical);
        if (sig == null) {
            log.warn("[node-storage-export] node={} gen={} served UNSIGNED (no signing key) — "
                    + "consumers fail closed", body.nodeFp(), body.generation());
        }
        return new SignedStorageExport(body, hash, sig, signer.publicKeyBase64(), sig != null);
    }

    /**
     * The canonical, deterministic byte encoding the content-hash + signature cover — the
     * SAME line-oriented form as the device export (NOT JSON, to avoid serializer ordering
     * ambiguity). The same bytes a node recomputes to verify.
     */
    static byte[] canonicalBytes(StorageExportBody body) {
        StringBuilder sb = new StringBuilder();
        sb.append("v1\n");
        sb.append("node=").append(nz(body.nodeFp())).append('\n');
        sb.append("generation=").append(body.generation()).append('\n');
        for (PoolEntry p : body.pools()) {
            sb.append("pool=").append(nz(p.poolId()))
              .append('\t').append("disk=").append(nz(p.diskSerial()))
              .append('\t').append("path=").append(nz(p.poolPath()))
              .append('\t').append("reserved=").append(p.reservedBytes())
              .append('\t').append("exclusive=").append(p.isExclusive())
              .append('\t').append("fs=").append(nz(p.filesystem()))
              .append('\n');
            for (AssignmentEntry a : p.assignments()) {
                sb.append("  assign=").append(nz(a.serviceName()))
                  .append('\t').append("pvc=").append(nz(a.pvcName()))
                  .append('\t').append("requested=").append(a.requestedBytes())
                  .append('\n');
            }
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
