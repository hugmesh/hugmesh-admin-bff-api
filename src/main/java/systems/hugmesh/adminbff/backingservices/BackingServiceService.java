package systems.hugmesh.adminbff.backingservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.backingservices.BackingServiceCatalog.BackingService;
import systems.hugmesh.adminbff.notification.NotificationOutbox;
import systems.hugmesh.adminbff.notification.NotificationOutboxRepository;
import systems.hugmesh.adminbff.web.dto.SetBackingServiceModeRequest;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Managed backing-services application service — the admin plane of the managed/self-hosted
 * axis (cloud-deploy DESIGN I8-DESIGN, Lane M3). Records a superadmin's per-service MODE INTENT
 * (self-hosted | managed) in the {@code backing_service_mode} ledger (schema 310), cloning the
 * {@link systems.hugmesh.adminbff.golive.GoLiveService} posture EXACTLY.
 *
 * <h3>INTENT ONLY (the pinned contract)</h3>
 * Recording a managed mode does NOT itself re-point any consumer or prune any workload. The live
 * flip is a build-time act (the generator's {@code gate_backing_services()}) or a future
 * reconciler act (the ships-dark {@link BackingServiceModeReconciler} skeleton, which LOGS ONLY
 * in v1). This service persists the desired-state row + emits a transactional-outbox event; the
 * (dark) {@link BackingServiceEffector} converges it later.
 *
 * <h3>SHIPS DARK</h3>
 * {@code app.backing-services.enabled=false} by default. While dark, the mutating verb refuses
 * early with a {@link BackingServiceDarkException} (mapped 503 by the controller) BEFORE any DB
 * write — but the AUTHORIZATION (SUPERADMIN role + step-up) is REAL and runs first at the
 * controller, and the READS (catalog + current state) stay live so the console renders its dark
 * state honestly. Mirrors {@link systems.hugmesh.adminbff.golive.GoLiveService}.
 *
 * <h3>TIER-3 = DOCS ONLY</h3>
 * A mode change for a docs-only (tier-3) service ({@code cassandra}, {@code harbor},
 * {@code vault-kv}, {@code vault-pki}) is REFUSED with a {@link BackingServiceDocsOnlyException}
 * (mapped 409 by the controller) — those managed swaps are architecturally blocked and ship as
 * design docs + emitted checklists, not code, in v1.
 *
 * <h3>NO SECRETS</h3>
 * {@code endpoint} is a non-secret coordinate; {@code credsRef} is a REFERENCE only. The wizard's
 * managed-cloud credentials route to keys-USB/ESO/Vault on the generator side — this service
 * refuses to know them (there is no field for the bytes).
 */
@Service
public class BackingServiceService {

    private static final Logger log = LoggerFactory.getLogger(BackingServiceService.class);

    /** Managed backing services are CROSS-DOMAIN infra; the notification_outbox row is stamped
     *  with the {@code default} single-issuer sentinel (the column's own back-compat default),
     *  not a per-brand domain. */
    private static final String INFRA_DOMAIN = "default";

    private final boolean enabled;
    private final BackingServiceModeRepository modes;
    /** The transactional-outbox sink: a {@code backing-service-mode-changed} notification_outbox
     *  row is written in the SAME reactive transaction as the mode-ledger row, so the outbox row
     *  exists IFF the mode row commits (the lossless transactional-outbox pattern
     *  {@code BackupService} / {@code SuspensionService} established). SHIPS DARK — nothing
     *  DELIVERS the row until a channel is enabled. */
    private final NotificationOutboxRepository outbox;
    /** Wraps the mode-ledger write + the outbox write in ONE reactive transaction so a failure of
     *  either leg rolls BOTH back (the BackupService transactional-outbox idiom). */
    private final TransactionalOperator tx;

    public BackingServiceService(@Value("${app.backing-services.enabled:false}") boolean enabled,
                                 BackingServiceModeRepository modes,
                                 NotificationOutboxRepository outbox,
                                 TransactionalOperator tx) {
        this.enabled = enabled;
        this.modes = modes;
        this.outbox = outbox;
        this.tx = tx;
    }

    public boolean isEnabled() {
        return enabled;
    }

    // ── reads (live even while dark — the console renders its state honestly) ─────────

    /** The static closed catalog (id / kind / tier / managed targets / notes; never a secret). */
    public List<BackingService> catalog() {
        return BackingServiceCatalog.SERVICES;
    }

    /**
     * The catalog JOINED with the CURRENT recorded mode per service — the console's main view.
     * A service with no recorded row reports {@code self-hosted} (the byte-identical default).
     * Docs-only (tier-3) rows are flagged so the UI renders them read-only.
     */
    public Mono<List<Map<String, Object>>> catalogWithState() {
        return modes.currentModes().map(current -> {
            List<Map<String, Object>> out = new java.util.ArrayList<>();
            for (BackingService s : BackingServiceCatalog.SERVICES) {
                BackingServiceMode mode = current.get(s.id());
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", s.id());
                m.put("kind", s.kind());
                m.put("tier", s.tier());
                m.put("docsOnly", s.docsOnly());
                m.put("displayName", s.displayName());
                m.put("awsTarget", s.awsTarget());
                m.put("azureTarget", s.azureTarget());
                m.put("notes", s.notes());
                // Current state: the recorded mode, or the self-hosted default when never recorded.
                m.put("currentMode", mode == null ? BackingServiceMode.MODE_SELF_HOSTED : mode.mode());
                m.put("endpoint", mode == null ? null : mode.endpoint());
                m.put("credsRef", mode == null ? null : mode.credsRef());
                m.put("generation", mode == null ? 0L : mode.generation());
                out.add(m);
            }
            return out;
        });
    }

    /** Full mode-change ledger, newest first (the console's audit/history view). */
    public Flux<BackingServiceMode> history() {
        return modes.history();
    }

    // ── record a mode intent (mutating; dark-gated; tier-3 refused; outbox in-tx) ────

    /**
     * Record a MODE intent for {@code serviceId}. Fail-closed: dark -> 503 (no write); unknown
     * id / bad vocabulary -> 400 (before any write); a docs-only (tier-3) service -> 409 (before
     * any write). On success, the mode-ledger row + a {@code backing-service-mode-changed} outbox
     * row are written in ONE reactive transaction, stamped with the next monotonic generation.
     */
    public Mono<BackingServiceMode> recordMode(String actor, String serviceId,
                                               SetBackingServiceModeRequest request) {
        if (!enabled) {
            return Mono.error(new BackingServiceDarkException());
        }
        String mode = normalize(request.mode());
        String endpoint = trimToNull(request.endpoint());
        String credsRef = trimToNull(request.credsRef());
        // Deferred so a vocabulary/docs-only refusal is a clean ERROR SIGNAL (mapped by the
        // controller), never an assembly-time throw that touches the ledger.
        return Mono.<BackingService>fromCallable(() -> validate(serviceId, mode, endpoint))
                .flatMap(svc -> modes.maxGeneration()
                        .flatMap(maxGen -> writeModeIntent(svc, serviceId, mode, endpoint, credsRef,
                                actor, maxGen + 1)));
    }

    /** Insert the mode-ledger row + the transactional-outbox row and commit both together. */
    private Mono<BackingServiceMode> writeModeIntent(BackingService svc, String serviceId, String mode,
                                                     String endpoint, String credsRef, String actor,
                                                     long generation) {
        return modes.insertRecorded(serviceId, mode, endpoint, credsRef, actor, generation)
                // The @system notifications subsystem (notification_outbox 062) writes an
                // infra-event row in the SAME reactive transaction as the ledger write.
                .flatMap(recorded -> emitModeChanged(svc, recorded).thenReturn(recorded))
                .doOnNext(recorded -> log.info("[backing-services] mode RECORDED service={} kind={} "
                                + "tier={} mode={} endpoint={} by={} gen={} — intent only (the "
                                + "effector converges later; ships dark in v1)",
                        recorded.serviceId(), svc.kind(), svc.tier(), recorded.mode(),
                        recorded.endpoint() == null ? "-" : recorded.endpoint(), actor,
                        recorded.generation()))
                // ── transaction boundary: the mode row + the outbox row commit together. ──
                .as(tx::transactional);
    }

    /**
     * Emit the {@code backing-service-mode-changed} outbox row for a just-recorded mode in the
     * SAME reactive transaction as the ledger write. The payload carries
     * service-id/kind/tier/mode ONLY — NEVER the actor, the managed endpoint, or the creds
     * reference (the neutral {@code @system} payload rule the backup events follow).
     */
    private Mono<Long> emitModeChanged(BackingService svc, BackingServiceMode recorded) {
        return outbox.insert(
                INFRA_DOMAIN,
                NotificationOutbox.SOURCE_BACKING_SERVICE_MODE,
                recorded.id(),
                NotificationOutbox.CATEGORY_BACKING_SERVICE_MODE_CHANGED,
                // NOTE: no actor, no endpoint, no credsRef — neutral, non-secret @system payload.
                modeChangedPayload(recorded.serviceId(), svc.kind(), svc.tier(), recorded.mode()));
    }

    /** Minimal, non-secret JSON payload. serviceId/kind/mode come from closed vocabularies and
     *  tier is an int, so no user-controlled text reaches the string (no escaping needed). */
    private static String modeChangedPayload(String serviceId, String kind, int tier, String mode) {
        return "{\"service_id\":\"" + serviceId + "\",\"kind\":\"" + kind + "\",\"tier\":" + tier
                + ",\"mode\":\"" + mode + "\"}";
    }

    // ── validation (vocabulary-pinned; refuses BEFORE any write) ──────────────────────

    /** Validate the id + mode vocabulary; returns the resolved catalog entry. Throws
     *  {@link BackingServiceValidationException} (-> 400) for an unknown id / bad mode / a managed
     *  mode with no endpoint, and {@link BackingServiceDocsOnlyException} (-> 409) for a tier-3
     *  docs-only service. */
    private static BackingService validate(String serviceId, String mode, String endpoint) {
        BackingService svc = BackingServiceCatalog.find(serviceId)
                .orElseThrow(() -> new BackingServiceValidationException(
                        "serviceId must be a known catalog id (see GET /bff/superadmin/backing-services)"));
        if (svc.docsOnly()) {
            throw new BackingServiceDocsOnlyException(svc.id());
        }
        if (!BackingServiceMode.MODE_SELF_HOSTED.equals(mode)
                && !BackingServiceMode.MODE_MANAGED.equals(mode)) {
            throw new BackingServiceValidationException(
                    "mode must be 'self-hosted' or 'managed'");
        }
        if (BackingServiceMode.MODE_MANAGED.equals(mode) && (endpoint == null || endpoint.isBlank())) {
            throw new BackingServiceValidationException(
                    "a managed mode requires an endpoint (the hosted service host/URL)");
        }
        return svc;
    }

    /** Trim + lowercase the pinned vocabulary (case-insensitive on input); blank -> null. */
    private static String normalize(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        return s.trim().toLowerCase(Locale.ROOT);
    }

    private static String trimToNull(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        return s.trim();
    }

    /** SHIPS DARK refusal (mapped to 503 by the controller). */
    public static class BackingServiceDarkException extends RuntimeException {
        public BackingServiceDarkException() {
            super("managed backing-services admin ships dark (app.backing-services.enabled=false)");
        }
    }

    /** A vocabulary/validation refusal (mapped to 400 by the controller). */
    public static class BackingServiceValidationException extends RuntimeException {
        public BackingServiceValidationException(String message) {
            super(message);
        }
    }

    /** A tier-3 DOCS-ONLY refusal (mapped to 409 by the controller). The managed swap for this
     *  service is architecturally blocked in v1 and ships as design docs + emitted checklists,
     *  not code. */
    public static class BackingServiceDocsOnlyException extends RuntimeException {
        public BackingServiceDocsOnlyException(String serviceId) {
            super("backing service '" + serviceId + "' is DOCS-ONLY in v1 — its managed cloud swap "
                    + "is architecturally blocked and ships as design docs + emitted checklists, "
                    + "not a runtime mode change; keep it self-hosted");
        }
    }
}
