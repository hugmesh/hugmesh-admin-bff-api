package net.hugmesh.adminbff.golive;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.RegistrySigner;
import net.hugmesh.adminbff.golive.GoLiveExportModels.GoLiveExportBody;
import net.hugmesh.adminbff.golive.GoLiveExportModels.GoLiveIntentEntry;
import net.hugmesh.adminbff.golive.GoLiveExportModels.SignedGoLiveExport;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Builds the SIGNED {@code go_live_intent} export — the ONE channel the in-cluster wizard
 * backend is allowed to effect go-live through (contract: signed intent only; the HOST-side
 * agent verifies + writes {@code /etc/hugmesh/go-live} itself). CLONES
 * {@link net.hugmesh.adminbff.domainregistry.DomainRegistryExportService} EXACTLY: a
 * pure deterministic {@code compile} + a detached-Ed25519 {@code sign} over canonical
 * line-oriented UTF-8 bytes (REUSING the same {@link RegistrySigner} bean), a MONOTONIC
 * generation + a fail-closed default-DENY posture.
 *
 * <h3>COMPILE PREDICATE (default-DENY)</h3>
 * The body carries EVERY {@code recorded} intent. A WITHDRAWN or already-APPLIED intent is
 * OMITTED — absence means "nothing (new) to apply", so the agent's steady state converges on
 * an empty body once every intent is acked. The intent ledger is cross-domain SUPERADMIN
 * infra (no per-node scoping): the whole recorded set IS the artefact.
 *
 * <h3>GENERATION (withdraw still advances)</h3>
 * The export generation is {@code max(generation)} over ALL rows — withdrawn included —
 * because the withdraw CAS stamps the withdrawn row with the next table-wide generation.
 * A withdraw thus shrinks the body while STRICTLY advancing the generation, so the agent's
 * strict-monotonic rollback guard accepts the removal instead of rejecting a "smaller" body
 * as a replay. An EMPTY ledger yields an empty signed body over generation 0 (never an error).
 *
 * <h3>FAIL-CLOSED</h3>
 * When no signing key is configured the export is served UNSIGNED and the agent MUST fail
 * closed (keep its last-good cache, apply nothing) — identical to the device/domain exports.
 */
@Service
public class GoLiveExportService {

    private static final Logger log = LoggerFactory.getLogger(GoLiveExportService.class);

    private final GoLiveIntentRepository intents;
    private final RegistrySigner signer;

    public GoLiveExportService(GoLiveIntentRepository intents, RegistrySigner signer) {
        this.intents = intents;
        this.signer = signer;
    }

    /**
     * Build + sign the intent export. The optional {@code node} fingerprint is pinned into
     * the header as PROVENANCE only (the ledger is cross-domain — nothing to scope).
     * Fail-closed: an empty ledger yields an empty signed body (never an error).
     */
    public Mono<SignedGoLiveExport> exportIntents(String node) {
        return intents.findAll().collectList()
                .map(rows -> sign(compile(node, rows)));
    }

    /**
     * Pure, deterministic compile of the export from the ledger rows. Unit-testable in
     * isolation. Emits ONLY {@code recorded} intents (withdrawn/applied -> absence); sorts by
     * {@code clusterDomain} so the canonical bytes (content-hash + signature) are reproducible
     * regardless of row order. The export generation is max over ALL rows (see class doc).
     */
    static GoLiveExportBody compile(String node, List<GoLiveIntent> rows) {
        List<GoLiveIntentEntry> entries = new ArrayList<>();
        long maxGen = 0L;
        for (GoLiveIntent i : rows) {
            // EVERY row's generation counts (withdraw bumps the withdrawn row, so the export
            // still advances) …
            maxGen = Math.max(maxGen, i.generation());
            // … but only a RECORDED intent rides the body (withdrawn/applied = absence).
            if (!GoLiveIntent.STATUS_RECORDED.equals(i.status())) {
                continue;
            }
            entries.add(new GoLiveIntentEntry(i.clusterDomain(), i.targetState(),
                    nz(i.exposureModel()), nz(i.provider()), nz(i.requestedBySubject()),
                    i.id(), i.generation()));
        }
        // Deterministic ordering so the content-hash + signature are reproducible.
        entries.sort(Comparator.comparing(GoLiveIntentEntry::clusterDomain));
        return new GoLiveExportBody(nz(node), maxGen, List.copyOf(entries));
    }

    /** Wrap a compiled body in the signed envelope: SHA-256 content-hash + detached Ed25519
     *  signature over the canonical body bytes. Unsigned when no key is configured (the agent
     *  fail-closes). REUSES the device-registry {@link RegistrySigner} bean. */
    SignedGoLiveExport sign(GoLiveExportBody body) {
        byte[] canonical = canonicalBytes(body);
        String hash = RegistrySigner.contentHash(canonical);
        String sig = signer.sign(canonical);
        if (sig == null) {
            log.warn("[go-live-export] node={} gen={} served UNSIGNED (no signing key) — agent fails closed",
                    body.node(), body.generation());
        }
        return new SignedGoLiveExport(body, hash, sig, signer.publicKeyBase64(), sig != null);
    }

    /**
     * The canonical, deterministic byte encoding the content-hash + signature cover — a
     * stable line-oriented form (NOT JSON), CLONING
     * {@code DomainRegistryExportService.canonicalBytes}:
     * <pre>
     *   v1-golive\n
     *   node=&lt;provenance-fp&gt;\n
     *   generation=&lt;long&gt;\n
     *   dom=&lt;clusterDomain&gt;\tstate=&lt;targetState&gt;\tmodel=&lt;exposureModel&gt;\tprovider=&lt;key&gt;\tby=&lt;subject&gt;\tintent=&lt;rowId&gt;\tgen=&lt;long&gt;\n  (one per entry)
     * </pre>
     * The same bytes the host go-live agent recomputes to verify.
     */
    static byte[] canonicalBytes(GoLiveExportBody body) {
        StringBuilder sb = new StringBuilder();
        sb.append("v1-golive\n");
        sb.append("node=").append(nz(body.node())).append('\n');
        sb.append("generation=").append(body.generation()).append('\n');
        for (GoLiveIntentEntry e : body.entries()) {
            sb.append("dom=").append(nz(e.clusterDomain()))
              .append('\t').append("state=").append(nz(e.targetState()))
              .append('\t').append("model=").append(nz(e.exposureModel()))
              .append('\t').append("provider=").append(nz(e.provider()))
              .append('\t').append("by=").append(nz(e.requestedBy()))
              .append('\t').append("intent=").append(nz(e.intentId()))
              .append('\t').append("gen=").append(e.generation())
              .append('\n');
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
