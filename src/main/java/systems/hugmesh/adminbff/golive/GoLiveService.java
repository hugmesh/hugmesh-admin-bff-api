package systems.hugmesh.adminbff.golive;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.golive.GoLiveProviderCatalog.GoLiveProvider;
import systems.hugmesh.adminbff.web.dto.RecordGoLiveIntentRequest;

import java.util.List;
import java.util.Locale;

/**
 * Go-live wizard application service — the admin web-UI half of go-live wizard v1.
 *
 * <h3>INTENT ONLY (the pinned contract)</h3>
 * The go-live switch is the HOST file {@code /etc/hugmesh/go-live} (+
 * {@code /etc/hugmesh/release-state}), converged by the host-side
 * {@code hugmesh-firewall-reconcile}. This in-cluster service NEVER writes that file and
 * NEVER reports it written: {@link #record} persists a {@code recorded} intent row, the
 * {@link GoLiveExportService signed export} carries it to the host go-live agent, and ONLY
 * that agent (after Ed25519 + monotonic-generation verification) flips the marker and later
 * acks {@code applied}. Rollback is the same flow with {@code targetState="internal"} (the
 * agent deletes the marker) — or simply {@link #withdraw withdrawing} a not-yet-applied
 * intent.
 *
 * <h3>SHIPS DARK</h3>
 * {@code app.go-live.enabled=false} by default. While dark, EVERY mutating verb refuses early
 * with a {@link GoLiveDarkException} (mapped to 503 by the controller) BEFORE any DB write —
 * but the AUTHORIZATION (SUPERADMIN role + step-up) is REAL and runs first at the controller,
 * and the READS (status / history / provider catalog) stay live so the wizard UI can render
 * its dark state honestly. Mirrors {@link
 * systems.hugmesh.adminbff.sshissue.AdminSshKeyIssuanceService} exactly.
 *
 * <h3>NO SECRETS</h3>
 * {@code provider} is a {@link GoLiveProviderCatalog} key. The wizard's collected tokens
 * (tunnel/DNS/DDNS) route to keys-USB/Vault on the generator side — this service refuses to
 * know them (there is no field to put them in).
 */
@Service
public class GoLiveService {

    private static final Logger log = LoggerFactory.getLogger(GoLiveService.class);

    private final boolean enabled;
    private final GoLiveIntentRepository intents;

    public GoLiveService(@Value("${app.go-live.enabled:false}") boolean enabled,
                         GoLiveIntentRepository intents) {
        this.enabled = enabled;
        this.intents = intents;
    }

    public boolean isEnabled() {
        return enabled;
    }

    // ── reads (live even while dark — the wizard renders its state honestly) ─────────

    /** Full intent history, newest first (the wizard's audit/preflight view). */
    public Flux<GoLiveIntent> history() {
        return intents.findAll();
    }

    /** The static v1 provider catalog (deep-link + autofill metadata; never a secret). */
    public List<GoLiveProvider> providers() {
        return GoLiveProviderCatalog.PROVIDERS;
    }

    // ── record (mutating; dark-gated; NEVER flips anything) ─────────────────────────

    /**
     * Record a go-live (or roll-back-internal) INTENT for {@code request.clusterDomain()}.
     * Fail-closed: dark -> 503 (no write); malformed vocabulary -> 400 (before any write).
     *
     * <p>SUPERSEDE semantics: at most ONE {@code recorded} intent per domain — any prior
     * recorded intent for the same domain is CAS-withdrawn first (each bump advancing the
     * monotonic generation), then the new row is inserted at the next generation. The
     * returned intent is {@code recorded} — NEVER {@code applied}; applying is the host
     * agent's act alone.
     */
    public Mono<GoLiveIntent> record(String actor, RecordGoLiveIntentRequest request) {
        if (!enabled) {
            return Mono.error(new GoLiveDarkException());
        }
        String domain = normalizeDomain(request.clusterDomain());
        String targetState = normalize(request.targetState());
        String exposureModel = normalize(request.exposureModel());
        String provider = normalize(request.provider());
        // Deferred so a vocabulary refusal is a clean ERROR SIGNAL (mapped to 400 by the
        // controller), never an assembly-time throw.
        return Mono.fromRunnable(() -> validate(domain, targetState, exposureModel, provider))
                // Withdraw any prior recorded intent for the same domain (supersede), then
                // insert. DEFERRED so a vocabulary refusal touches the ledger NOT AT ALL.
                .thenMany(Flux.defer(() -> intents.findRecordedForDomain(domain)))
                .concatMap(prior -> intents.maxGeneration()
                        .flatMap(maxGen -> intents.withdraw(prior.id(), maxGen + 1)))
                // DEFERRED re-read: the insert's generation stamp must observe the supersede
                // withdraws above (an eager .then(maxGeneration()) would read the STALE max).
                .then(Mono.defer(intents::maxGeneration))
                .flatMap(maxGen -> intents.insertRecorded(domain, targetState, exposureModel,
                        provider, request.note(), actor, maxGen + 1))
                .doOnNext(i -> log.info("[go-live] intent RECORDED id={} domain={} target={} "
                                + "model={} provider={} by={} gen={} — host agent applies via the "
                                + "signed export (the BFF never writes the marker)",
                        i.id(), i.clusterDomain(), i.targetState(), i.exposureModel(),
                        i.provider(), actor, i.generation()));
    }

    // ── withdraw (mutating; dark-gated) ──────────────────────────────────────────────

    /**
     * Withdraw a {@code recorded} intent: CAS {@code recorded -> withdrawn} (audited, never
     * deleted), stamping the next monotonic generation so the signed export advances past the
     * removal. Returns rows-updated (1 = withdrawn, 0 = absent / already withdrawn/applied).
     * An already-APPLIED intent cannot be withdrawn — roll back by recording a new
     * {@code targetState="internal"} intent instead.
     */
    public Mono<Long> withdraw(String actor, String id) {
        if (!enabled) {
            return Mono.error(new GoLiveDarkException());
        }
        return intents.maxGeneration()
                .flatMap(maxGen -> intents.withdraw(id, maxGen + 1))
                .doOnNext(n -> log.info("[go-live] intent WITHDRAW id={} by={} rows={}", id, actor, n));
    }

    // ── applied-ack (mutating; HOST-AGENT surface; NOT dark-gated — see below) ──────

    /**
     * HOST-AGENT applied-ack: CAS {@code recorded -> applied} for ONE intent row, called from
     * {@code POST /bff/internal/go-live/{intentId}/applied-ack} (mTLS-trust-boundary, no JWT —
     * mirrors {@link systems.hugmesh.adminbff.imagegen.ImageBuildIngestController}). This is
     * the ONLY code path in this service that ever writes {@code applied}/{@code appliedAt}/
     * {@code appliedBy} — record/withdraw never touch them (the pinned intent-only contract).
     *
     * <h3>Which "generation"? (load-bearing)</h3>
     * {@code generation} here MUST be the intent's OWN per-row generation stamp — the {@code
     * gen=} field the host agent read off THAT entry's line in the canonical export bytes
     * ({@link GoLiveExportModels.GoLiveIntentEntry#generation()}) — NEVER the export
     * envelope's top-level {@code generation}, which is {@code max(generation)} over EVERY row
     * in the ledger ({@link GoLiveExportModels.GoLiveExportBody#generation()}; see that class's
     * javadoc). The repository CAS binds {@code id} AND this {@code generation} together in the
     * WHERE clause. Because a superseded intent is CAS-withdrawn (never mutated in place) and
     * its replacement is always inserted under a BRAND-NEW DB-generated id, a stale ack that
     * still names the old, now-superseded id+generation simply matches zero rows — it can never
     * land on the new superseding row.
     *
     * <h3>Not dark-gated (deliberate)</h3>
     * Unlike {@link #record}/{@link #withdraw}, this does NOT refuse while {@code
     * app.go-live.enabled=false}: a row can only be {@code recorded} in the first place while
     * the wizard was enabled, and finishing an in-flight ack after a later dark-toggle is
     * correctness-positive, not a hazard. Mirrors {@code ImageBuildIngestController.ingest}
     * (also un-gated by any feature flag).
     *
     * <p>Returns rows-updated: {@code 1} = applied now, {@code 0} = absent / not recorded /
     * generation mismatch — ALL of which are a normal, expected, idempotent no-op for a host
     * agent that retries this call every reconcile cycle, never a hard failure.
     */
    public Mono<Long> applyAck(String intentId, long generation, String appliedBy) {
        return intents.markApplied(intentId, generation, appliedBy)
                .doOnNext(n -> log.info("[go-live] intent APPLIED-ACK id={} gen={} by={} rows={}",
                        intentId, generation, appliedBy, n));
    }

    // ── validation (vocabulary-pinned, mirrors the DB CHECKs; 400 before any write) ──

    private static void validate(String domain, String targetState, String exposureModel,
                                 String provider) {
        if (domain == null || domain.isBlank()) {
            throw new GoLiveValidationException("clusterDomain is required");
        }
        if (!GoLiveIntent.TARGET_PUBLIC.equals(targetState)
                && !GoLiveIntent.TARGET_INTERNAL.equals(targetState)) {
            throw new GoLiveValidationException(
                    "targetState must be 'public' or 'internal' (the host RELEASE_STATE vocabulary)");
        }
        if (GoLiveIntent.TARGET_INTERNAL.equals(targetState)) {
            // Roll-back intent: no edge to provision — model/provider must be absent.
            if (exposureModel != null || provider != null) {
                throw new GoLiveValidationException(
                        "a roll-back-internal intent carries no exposureModel/provider");
            }
            return;
        }
        // Go-PUBLIC intent: model + provider are REQUIRED and must agree with the catalog.
        if (exposureModel == null) {
            throw new GoLiveValidationException(
                    "exposureModel is required to go public (tunnel | public_dns | funnel)");
        }
        GoLiveProvider p = GoLiveProviderCatalog.find(provider)
                .orElseThrow(() -> new GoLiveValidationException(
                        "provider must be a known catalog key (see GET /bff/admin/go-live/providers)"));
        if (!p.exposureModel().equals(exposureModel)) {
            throw new GoLiveValidationException("provider '" + p.key()
                    + "' serves exposureModel '" + p.exposureModel() + "', not '" + exposureModel + "'");
        }
    }

    /** Trim + lowercase (domains and the pinned vocabularies are case-insensitive on input,
     *  canonical-lowercase at rest); blank -> null. */
    private static String normalize(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        return s.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeDomain(String s) {
        return normalize(s);
    }

    /** SHIPS DARK refusal (mapped to 503 by the controller). */
    public static class GoLiveDarkException extends RuntimeException {
        public GoLiveDarkException() {
            super("go-live wizard ships dark (app.go-live.enabled=false)");
        }
    }

    /** A vocabulary/validation refusal (mapped to 400 by the controller). */
    public static class GoLiveValidationException extends RuntimeException {
        public GoLiveValidationException(String message) {
            super(message);
        }
    }
}
