package systems.hugmesh.adminbff.device;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.device.ExportModels.AuthorizedOperator;
import systems.hugmesh.adminbff.device.ExportModels.ExportBody;
import systems.hugmesh.adminbff.device.ExportModels.SignedExport;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Builds the UNSCOPED, SIGNED per-mesh device-registry export [FIX-SIGNCACHE] — the ONE
 * artefact BOTH enforcement layers compile from (per-node sshd
 * {@code AuthorizedKeysCommand} + headscale policy). The BFF NEVER evaluates SSH
 * authorization at connect time; it emits the compiled authorized-operator set computed
 * here straight from the AUTH PREDICATE, then signs it.
 *
 * <h3>AUTH PREDICATE (default-DENY, total, monotone)</h3>
 * For each node {@code D} in the mesh and each ACTIVE license {@code L} (operator
 * {@code P = L.operator}), an entry is emitted iff:
 * <ul>
 *   <li>{@code D.owner_type == ADMIN}:
 *     <ul>
 *       <li>DEVICE: {@code L.device_id == D.id} → ALLOW via {@code DEVICE-LICENSE}; OR</li>
 *       <li>DOMAIN: {@code L.target_domain == D.domain} → ALLOW via {@code DOMAIN-LICENSE}.</li>
 *     </ul>
 *     (An ADMIN-domain admin reaches an own-domain node it is licensed to.)</li>
 *   <li>{@code D.owner_type == SUPERADMIN}: NEVER emitted. POST-VERIFY CORRECTION
 *       (2026-06-12): the unscoped signed export cannot see operator roles, so it must NOT
 *       carry SUPERADMIN access. {@code grantDevice()} REJECTS a SUPERADMIN-owned device,
 *       so no license can exist on such a node; this compiler additionally SKIPS
 *       superadmin-owned nodes (defense-in-depth). SUPERADMIN mesh-reach is enforced
 *       ENTIRELY by the deferred Layer-A headscale policy (per-tenant OIDC user +
 *       mesh-membership + a SUPERADMIN rule), NOT by the BFF.</li>
 * </ul>
 * Every emitted entry pins the EXACT key fingerprints [FIX-PINKEY] the operator may
 * present on that node; an entry whose license pins NO key is dropped (fail-closed). No
 * license row → no entry (default-deny). MOD/USER hold no license rows, so they never
 * appear.
 *
 * <p><b>Layer-A/B acceptance (residual, (e)):</b> the enforcement layers MUST
 * independently re-derive the operator's role from the validated issuer (DomainRegistry)
 * and DENY any ADMIN operator on a SUPERADMIN-owned node; the {@code via} field is
 * PROVENANCE only, never a role assertion. Cross-superadmin mesh-membership scoping is a
 * headscale concern, not a BFF table — explicitly out of scope here.
 *
 * <p>The compiled body is canonicalised deterministically (stable operator/host ordering)
 * so the {@code content-hash} + detached signature are reproducible; {@code generation}
 * is {@code max(license.generation)} for the node's rollback guard.
 */
@Service
public class DeviceRegistryExportService {

    private static final Logger log = LoggerFactory.getLogger(DeviceRegistryExportService.class);

    private final DeviceRegistryRepository devices;
    private final SshLicenseRepository licenses;
    private final RegistrySigner signer;

    public DeviceRegistryExportService(DeviceRegistryRepository devices, SshLicenseRepository licenses,
                                       RegistrySigner signer) {
        this.devices = devices;
        this.licenses = licenses;
        this.signer = signer;
    }

    /**
     * Build + sign the export for one mesh (UNSCOPED — the export is the cross-brand
     * source of truth; the admin VIEW is per-tenant, but enforcement is mesh-wide). This
     * is the CONTROL-PLANE (Layer-A) shape: the signed body carries EVERY node in the mesh
     * so the headscale policy generator can compile the whole mesh's authorized edges.
     */
    public Mono<SignedExport> exportMesh(String meshId) {
        Mono<List<Device>> nodesMono = devices.listByMesh(meshId).collectList();
        Mono<List<SshLicense>> licMono = licenses.listActiveAll().collectList();
        return Mono.zip(nodesMono, licMono)
                .map(t -> sign(compile(meshId, t.getT1(), t.getT2())));
    }

    /**
     * Build + sign the PER-NODE export for ONE device, addressed by its stable
     * {@code machine_key_fp} [CONFIDENTIALITY HARDENING]. The signed body carries ONLY the
     * authorized-operators for THAT ONE node (the AUTH PREDICATE applied to a single-element
     * node set) — NEVER the rest of the mesh. A Layer-B node (the per-node sshd
     * {@code AuthorizedKeysCommand}) caches this and so NEVER learns any OTHER node's (or any
     * other domain's) operator names / key fingerprints. The canonical-bytes header still
     * pins the node's resolved {@code mesh_id} and the same monotonic {@code generation}; the
     * detached Ed25519 signature is identical in shape — just a NARROWER {@code operators[]}.
     *
     * <p>The {@code machine_key_fp -> mesh} resolution is UNSCOPED ({@code findByMachineKey})
     * and FAIL-CLOSED: an UNKNOWN fingerprint yields an EMPTY (but signed) body over an empty
     * mesh header — NOT an error, so a probe of an unknown fp leaks NOTHING (no node count, no
     * mesh id, no operator). The predicate that decides which operators a node authorizes is
     * UNCHANGED — only the candidate node set is narrowed to the one resolved device.
     */
    public Mono<SignedExport> exportNode(String machineKeyFp) {
        return devices.findByMachineKey(machineKeyFp)
                .flatMap(node -> licenses.listActiveAll().collectList()
                        .map(lics -> sign(compile(node.meshId(), List.of(node), lics))))
                // fail-closed: unknown fp -> empty signed body, never a leaky error.
                .switchIfEmpty(Mono.fromSupplier(() -> sign(compile("", List.of(), List.of()))));
    }

    /**
     * Compile the per-mesh authorized-operator set from the AUTH PREDICATE. Pure +
     * deterministic (no IO) so it is unit-testable in isolation against the predicate.
     */
    static ExportBody compile(String meshId, List<Device> nodes, List<SshLicense> activeLicenses) {
        // Index device licenses by device id, domain licenses by target domain.
        Map<String, List<SshLicense>> byDevice = activeLicenses.stream()
                .filter(SshLicense::isDeviceScoped)
                .filter(l -> l.deviceId() != null)
                .collect(Collectors.groupingBy(SshLicense::deviceId));
        Map<String, List<SshLicense>> byDomain = activeLicenses.stream()
                .filter(SshLicense::isDomainScoped)
                .filter(l -> l.targetDomain() != null)
                .collect(Collectors.groupingBy(SshLicense::targetDomain));

        long generation = activeLicenses.stream().mapToLong(SshLicense::generation).max().orElse(0L);

        List<AuthorizedOperator> operators = new ArrayList<>();
        for (Device d : nodes) {
            // POST-VERIFY CORRECTION (2026-06-12): the export carries ONLY explicit ADMIN
            // licenses (via ∈ {DEVICE-LICENSE, DOMAIN-LICENSE}). The former
            // `d.isSuperadminOwned() -> via=SUPERADMIN-MESH` branch is REMOVED: it modelled
            // SUPERADMIN mesh-reach in the WRONG layer. The unscoped signed export cannot
            // see operator roles, so it must never assert SUPERADMIN access. SUPERADMIN
            // reach is enforced ENTIRELY by the deferred Layer-A headscale policy
            // (per-tenant OIDC user + mesh-membership + a SUPERADMIN rule) — headscale is
            // the mesh-membership source of truth, never the BFF. With grantDevice()
            // rejecting a SUPERADMIN-owned target, no license can exist on such a node; we
            // additionally SKIP superadmin-owned nodes here (defense-in-depth against any
            // stale pre-correction row) so a superadmin-owned node NEVER appears in the
            // export at all.
            if (d.isSuperadminOwned()) {
                continue;
            }
            // DEVICE-scoped licenses targeting THIS (ADMIN-owned) node.
            for (SshLicense l : byDevice.getOrDefault(d.id(), List.of())) {
                addEntry(operators, d, l, AuthorizedOperator.VIA_DEVICE_LICENSE);
            }
            // DOMAIN-scoped licenses whose target == THIS node's residency domain.
            for (SshLicense l : byDomain.getOrDefault(d.domain(), List.of())) {
                addEntry(operators, d, l, AuthorizedOperator.VIA_DOMAIN_LICENSE);
            }
        }

        // Deterministic ordering so the content-hash + signature are reproducible.
        operators.sort(Comparator
                .comparing(AuthorizedOperator::operator)
                .thenComparing(AuthorizedOperator::machineKeyFp)
                .thenComparing(AuthorizedOperator::via));
        return new ExportBody(meshId, generation, List.copyOf(operators));
    }

    /** Emit one entry for (node, license) iff the license pins at least one key
     *  [FIX-PINKEY]; an entry pinning NO key is dropped (fail-closed). */
    private static void addEntry(List<AuthorizedOperator> out, Device d, SshLicense l, String via) {
        List<String> fps = l.fingerprints();
        if (fps.isEmpty()) return;   // pinned-key required — no key, no entry
        out.add(new AuthorizedOperator(l.operator(), d.machineKeyFp(), d.hostname(), fps, via));
    }

    /** Wrap a compiled body in the signed envelope: SHA-256 content-hash + detached
     *  Ed25519 signature over the canonical body bytes [FIX-SIGNCACHE]. Unsigned when no
     *  key is configured (consumer fail-closes). */
    SignedExport sign(ExportBody body) {
        byte[] canonical = canonicalBytes(body);
        String hash = RegistrySigner.contentHash(canonical);
        String sig = signer.sign(canonical);
        if (sig == null) {
            log.warn("[device-export] mesh={} gen={} served UNSIGNED (no signing key) — consumers fail closed",
                    body.meshId(), body.generation());
        }
        return new SignedExport(body, hash, sig, signer.publicKeyBase64(), sig != null);
    }

    /**
     * The canonical, deterministic byte encoding the content-hash + signature cover —
     * {@code {generation, mesh_id, content-hash-of-entries}} flattened to a stable
     * line-oriented form (NOT JSON, to avoid any serializer field-ordering ambiguity).
     * The same bytes a node recomputes to verify.
     */
    static byte[] canonicalBytes(ExportBody body) {
        StringBuilder sb = new StringBuilder();
        sb.append("v1\n");
        sb.append("mesh=").append(nz(body.meshId())).append('\n');
        sb.append("generation=").append(body.generation()).append('\n');
        for (AuthorizedOperator op : body.operators()) {
            sb.append("op=").append(nz(op.operator()))
              .append('\t').append("fp=").append(nz(op.machineKeyFp()))
              .append('\t').append("host=").append(nz(op.hostname()))
              .append('\t').append("via=").append(nz(op.via()))
              .append('\t').append("keys=").append(String.join(",", op.keyFingerprints()))
              .append('\n');
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
