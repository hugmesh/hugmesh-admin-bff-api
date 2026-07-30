package systems.hugmesh.adminbff.egressvpn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.device.Device;
import systems.hugmesh.adminbff.device.DeviceRegistryRepository;
import systems.hugmesh.adminbff.device.RegistrySigner;
import systems.hugmesh.adminbff.egressvpn.VpnExportModels.SignedVpnExport;
import systems.hugmesh.adminbff.egressvpn.VpnExportModels.VpnEgressEntry;
import systems.hugmesh.adminbff.egressvpn.VpnExportModels.VpnExportBody;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Builds the SIGNED PER-NODE egress-VPN export — the ONE artefact the node-level
 * reconcile agent compiles into the {@code hugmesh-egress-vpn} service's
 * {@code active.conf} + the assigned-service set. CLONES
 * {@link systems.hugmesh.adminbff.device.DeviceRegistryExportService} EXACTLY: a pure
 * deterministic {@code compile} + a detached-Ed25519 {@code sign} over canonical
 * line-oriented UTF-8 bytes (REUSING the same {@link RegistrySigner} bean), the same
 * monotonic generation + fail-closed-on-unknown-node posture.
 *
 * <h3>COMPILE PREDICATE (default-DENY)</h3>
 * For the node resolved by its {@code machine_key_fp}, an entry is emitted for each ACTIVE
 * {@link VpnConfig} referenced by:
 * <ul>
 *   <li>an ACTIVE DEVICE assignment whose {@code target_node_id == fp}, OR</li>
 *   <li>an ACTIVE DOMAIN assignment whose {@code target_domain == node.domain()}.</li>
 * </ul>
 * A SUPERADMIN-owned node NEVER gets an entry (core nodes are not domain-public-egress
 * targets — and the service rejects such assignments anyway; this is defence-in-depth). A
 * config that is no longer active is skipped (a stale assignment yields nothing). The
 * per-config {@code serviceSlugs} are the union of the matching assignments' slugs ({@code
 * []} when any matching assignment is "all services", which subsumes the narrowed ones).
 *
 * <p>The {@code machine_key_fp -> node} resolution is UNSCOPED and FAIL-CLOSED: an UNKNOWN
 * fingerprint yields an EMPTY (but signed) body — NOT an error, so a probe leaks nothing.
 * {@code generation} is the max over the contributing config + assignment generations so
 * the agent's strict-monotonic rollback guard rejects a replayed payload.
 */
@Service
public class VpnExportService {

    private static final Logger log = LoggerFactory.getLogger(VpnExportService.class);

    private final DeviceRegistryRepository devices;
    private final VpnConfigRepository configs;
    private final VpnNodeAssignmentRepository assignments;
    private final RegistrySigner signer;

    public VpnExportService(DeviceRegistryRepository devices, VpnConfigRepository configs,
                            VpnNodeAssignmentRepository assignments, RegistrySigner signer) {
        this.devices = devices;
        this.configs = configs;
        this.assignments = assignments;
        this.signer = signer;
    }

    /**
     * Build + sign the per-node export for the device addressed by its stable
     * {@code machine_key_fp}. Fail-closed: an unknown fp (or a SUPERADMIN-owned node)
     * yields an empty signed body over an empty node header.
     */
    public Mono<SignedVpnExport> exportNode(String machineKeyFp) {
        return devices.findByMachineKey(machineKeyFp)
                .filter(node -> !node.isSuperadminOwned())
                .flatMap(node -> Mono.zip(
                                configs.listActiveAll().collectList(),
                                assignments.listActiveAll().collectList())
                        .map(t -> sign(compile(node, t.getT1(), t.getT2()))))
                // fail-closed: unknown / superadmin-owned fp -> empty signed body.
                .switchIfEmpty(Mono.fromSupplier(() -> sign(compile(machineKeyFp, List.of(), List.of()))));
    }

    /** Pure, deterministic compile of the per-node egress set from the active configs +
     *  assignments. Unit-testable in isolation. */
    static VpnExportBody compile(Device node, List<VpnConfig> activeConfigs,
                                 List<VpnNodeAssignment> activeAssignments) {
        Map<String, VpnConfig> configById = new LinkedHashMap<>();
        for (VpnConfig c : activeConfigs) configById.put(c.id(), c);

        // Group the matching assignments by config id; collect the service-slug union.
        // A null slug ("all services") wins: the entry then carries an empty slug list.
        Map<String, TreeSet<String>> slugsByConfig = new LinkedHashMap<>();
        Map<String, Boolean> allServicesByConfig = new LinkedHashMap<>();
        long maxGen = 0L;
        for (VpnNodeAssignment a : activeAssignments) {
            boolean matches = (a.isDeviceScoped() && node.machineKeyFp().equals(a.targetNodeId()))
                    || (a.isDomainScoped() && node.domain().equals(a.targetDomain()));
            if (!matches) continue;
            VpnConfig cfg = configById.get(a.configId());
            if (cfg == null) continue; // config revoked — skip (default-deny)
            maxGen = Math.max(maxGen, Math.max(a.generation(), cfg.generation()));
            slugsByConfig.computeIfAbsent(cfg.id(), k -> new TreeSet<>());
            if (a.serviceSlug() == null || a.serviceSlug().isBlank()) {
                allServicesByConfig.put(cfg.id(), Boolean.TRUE);
            } else {
                slugsByConfig.get(cfg.id()).add(a.serviceSlug());
            }
        }

        List<VpnEgressEntry> entries = new ArrayList<>();
        for (Map.Entry<String, TreeSet<String>> e : slugsByConfig.entrySet()) {
            VpnConfig cfg = configById.get(e.getKey());
            List<String> slugs = Boolean.TRUE.equals(allServicesByConfig.get(e.getKey()))
                    ? List.of()                         // "all services" subsumes the narrowed ones
                    : List.copyOf(e.getValue());
            entries.add(new VpnEgressEntry(cfg.name(), cfg.kind(), cfg.secretRef(), cfg.endpoint(), slugs));
        }
        // Deterministic ordering so the content-hash + signature are reproducible.
        entries.sort(Comparator.comparing(VpnEgressEntry::configName));
        return new VpnExportBody(node.machineKeyFp(), maxGen, List.copyOf(entries));
    }

    /** Empty-body overload for the fail-closed (unknown fp) path. */
    static VpnExportBody compile(String fp, List<VpnConfig> ignoredConfigs,
                                 List<VpnNodeAssignment> ignoredAssignments) {
        return new VpnExportBody("", 0L, List.of());
    }

    /** Wrap a compiled body in the signed envelope: SHA-256 content-hash + detached
     *  Ed25519 signature over the canonical body bytes. Unsigned when no key is configured
     *  (agent fail-closes). REUSES the device-registry RegistrySigner bean. */
    SignedVpnExport sign(VpnExportBody body) {
        byte[] canonical = canonicalBytes(body);
        String hash = RegistrySigner.contentHash(canonical);
        String sig = signer.sign(canonical);
        if (sig == null) {
            log.warn("[egress-vpn-export] node={} gen={} served UNSIGNED (no signing key) — agent fails closed",
                    body.node(), body.generation());
        }
        return new SignedVpnExport(body, hash, sig, signer.publicKeyBase64(), sig != null);
    }

    /**
     * The canonical, deterministic byte encoding the content-hash + signature cover — a
     * stable line-oriented form (NOT JSON), CLONING
     * {@code DeviceRegistryExportService.canonicalBytes}:
     * <pre>
     *   v1-vpn\n
     *   node=&lt;machineKeyFp&gt;\n
     *   generation=&lt;long&gt;\n
     *   cfg=&lt;name&gt;\tkind=&lt;kind&gt;\tsecret=&lt;secretRef&gt;\tendpoint=&lt;ep&gt;\tservices=&lt;csv&gt;\n  (one per entry)
     * </pre>
     * The same bytes the node agent recomputes to verify.
     */
    static byte[] canonicalBytes(VpnExportBody body) {
        StringBuilder sb = new StringBuilder();
        sb.append("v1-vpn\n");
        sb.append("node=").append(nz(body.node())).append('\n');
        sb.append("generation=").append(body.generation()).append('\n');
        for (VpnEgressEntry e : body.entries()) {
            sb.append("cfg=").append(nz(e.configName()))
              .append('\t').append("kind=").append(nz(e.kind()))
              .append('\t').append("secret=").append(nz(e.secretRef()))
              .append('\t').append("endpoint=").append(nz(e.endpoint()))
              .append('\t').append("services=").append(String.join(",", e.serviceSlugs()))
              .append('\n');
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
