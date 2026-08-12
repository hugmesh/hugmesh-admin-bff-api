package net.hugmesh.adminbff.domainregistry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.RegistrySigner;
import net.hugmesh.adminbff.domainregistry.DomainExportModels.DomainEntry;
import net.hugmesh.adminbff.domainregistry.DomainExportModels.DomainExportBody;
import net.hugmesh.adminbff.domainregistry.DomainExportModels.SignedDomainExport;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Builds the SIGNED {@code domain_registry} export — the ONE missing export symmetry for
 * runtime add-domain provisioning. CLONES
 * {@link net.hugmesh.adminbff.device.DeviceRegistryExportService} and
 * {@link net.hugmesh.adminbff.egressvpn.VpnExportService} EXACTLY: a pure
 * deterministic {@code compile} + a detached-Ed25519 {@code sign} over canonical
 * line-oriented UTF-8 bytes (REUSING the same {@link RegistrySigner} bean from the {@code
 * device} package), a MONOTONIC generation + a fail-closed default-DENY posture.
 *
 * <h3>COMPILE PREDICATE (default-DENY, cross-domain)</h3>
 * The body carries EVERY {@code enabled == true} domain. A SOFT-DISABLED domain
 * ({@code enabled == false}) is OMITTED — a declarative registry never asks the reconcile
 * agent to materialise a disabled brand (it is the agent's de-provision signal: absence).
 * The registry is the REGISTRY OF BRANDS itself (no per-row tenant discriminator, see
 * Liquibase 012) so — unlike the per-node device/VPN/storage exports — there is NOTHING to
 * scope per-node: the whole enabled brand list is the artefact the generator domain-reconcile
 * compiles into the per-domain CA loop + the brand-list ArgoCD ApplicationSet.
 *
 * <h3>FAIL-CLOSED / EMPTY</h3>
 * An EMPTY registry (or one with no enabled domains) yields an EMPTY (but signed) body over
 * generation 0 — never an error, so a probe leaks nothing and the agent verifies + applies a
 * deterministic empty set (default-DENY: no domain → no brand materialised). The detached
 * Ed25519 signature is identical in shape whether the body is full or empty; the agent
 * verifies against the BAKED key-USB public half and FAILS CLOSED (keeps its last-good cache)
 * on an unsigned / tampered / rolled-back (generation &le; current) payload.
 *
 * <p>{@code generation} is {@code max(row.last_reconciled_generation)} with a +1 floor when
 * the registry is non-empty, so a freshly registered registry (all rows at the band-190
 * default 0) still advances past a consumer's last-good 0 the FIRST time and the agent's
 * strict-monotonic guard accepts it; thereafter the effector's per-row generation bumps drive
 * it forward.
 */
@Service
public class DomainRegistryExportService {

    private static final Logger log = LoggerFactory.getLogger(DomainRegistryExportService.class);

    private final DomainRegistryRepository domains;
    private final RegistrySigner signer;

    public DomainRegistryExportService(DomainRegistryRepository domains, RegistrySigner signer) {
        this.domains = domains;
        this.signer = signer;
    }

    /**
     * Build + sign the cross-domain registry export. The optional {@code node} fingerprint is
     * pinned into the header as PROVENANCE only (it does NOT scope the body — the registry is
     * cross-domain). An unknown/blank fingerprint is fine: it changes nothing but the header.
     * Fail-closed: an empty registry yields an empty signed body (never an error).
     */
    public Mono<SignedDomainExport> exportRegistry(String node) {
        return domains.findAll().collectList()
                .map(rows -> sign(compile(node, rows)));
    }

    /**
     * Pure, deterministic compile of the cross-domain export from the registry rows. Unit-
     * testable in isolation. Drops SOFT-DISABLED domains; sorts the surviving entries by
     * {@code clusterDomain} so the canonical bytes (and the content-hash + signature) are
     * reproducible regardless of the repository's row order.
     */
    static DomainExportBody compile(String node, List<DomainRegistration> rows) {
        List<DomainEntry> entries = new ArrayList<>();
        long maxRowGen = 0L;
        for (DomainRegistration d : rows) {
            if (!d.enabled()) {
                continue;   // soft-disabled -> omitted (de-provision = absence)
            }
            maxRowGen = Math.max(maxRowGen, d.lastReconciledGeneration());
            entries.add(new DomainEntry(d.clusterDomain(), d.brand(), d.org(), d.caRef(),
                    d.nsPrefix(), d.casdoorOrg(), d.meshTag(),
                    d.caProvisioned(), d.appsetRegistered(), d.lastReconciledGeneration()));
        }
        // Deterministic ordering so the content-hash + signature are reproducible.
        entries.sort(Comparator.comparing(DomainEntry::clusterDomain));
        // +1 floor over the max row generation when non-empty, so a fresh registry (all rows
        // at default 0) advances past a consumer's last-good 0 on the first fetch; an empty
        // registry stays at 0 (a deterministic empty signed body).
        long generation = entries.isEmpty() ? 0L : maxRowGen + 1L;
        return new DomainExportBody(nz(node), generation, List.copyOf(entries));
    }

    /** Wrap a compiled body in the signed envelope: SHA-256 content-hash + detached Ed25519
     *  signature over the canonical body bytes. Unsigned when no key is configured (the agent
     *  fail-closes). REUSES the device-registry {@link RegistrySigner} bean. */
    SignedDomainExport sign(DomainExportBody body) {
        byte[] canonical = canonicalBytes(body);
        String hash = RegistrySigner.contentHash(canonical);
        String sig = signer.sign(canonical);
        if (sig == null) {
            log.warn("[domain-export] node={} gen={} served UNSIGNED (no signing key) — agent fails closed",
                    body.node(), body.generation());
        }
        return new SignedDomainExport(body, hash, sig, signer.publicKeyBase64(), sig != null);
    }

    /**
     * The canonical, deterministic byte encoding the content-hash + signature cover — a
     * stable line-oriented form (NOT JSON), CLONING
     * {@code DeviceRegistryExportService.canonicalBytes} / {@code VpnExportService.canonicalBytes}:
     * <pre>
     *   v1-domain\n
     *   node=&lt;provenance-fp&gt;\n
     *   generation=&lt;long&gt;\n
     *   dom=&lt;clusterDomain&gt;\tbrand=&lt;brand&gt;\torg=&lt;org&gt;\tca=&lt;caRef&gt;\tns=&lt;nsPrefix&gt;\tcasdoor=&lt;casdoorOrg&gt;\tmesh=&lt;meshTag&gt;\tca_prov=&lt;bool&gt;\tappset=&lt;bool&gt;\tgen=&lt;long&gt;\n  (one per entry)
     * </pre>
     * The same bytes the generator domain-reconcile agent recomputes to verify.
     */
    static byte[] canonicalBytes(DomainExportBody body) {
        StringBuilder sb = new StringBuilder();
        sb.append("v1-domain\n");
        sb.append("node=").append(nz(body.node())).append('\n');
        sb.append("generation=").append(body.generation()).append('\n');
        for (DomainEntry e : body.entries()) {
            sb.append("dom=").append(nz(e.clusterDomain()))
              .append('\t').append("brand=").append(nz(e.brand()))
              .append('\t').append("org=").append(nz(e.org()))
              .append('\t').append("ca=").append(nz(e.caRef()))
              .append('\t').append("ns=").append(nz(e.nsPrefix()))
              .append('\t').append("casdoor=").append(nz(e.casdoorOrg()))
              .append('\t').append("mesh=").append(nz(e.meshTag()))
              .append('\t').append("ca_prov=").append(e.caProvisioned())
              .append('\t').append("appset=").append(e.appsetRegistered())
              .append('\t').append("gen=").append(e.generation())
              .append('\n');
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
