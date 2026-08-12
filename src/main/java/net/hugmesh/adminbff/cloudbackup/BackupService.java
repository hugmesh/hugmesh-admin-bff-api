package net.hugmesh.adminbff.cloudbackup;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.notification.BackupNotificationPayload;
import net.hugmesh.adminbff.notification.NotificationOutbox;
import net.hugmesh.adminbff.notification.NotificationOutboxRepository;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.List;

/**
 * Write/read surface for the per-domain + superadmin TOTAL-CLOUD backups catalog (schema 160).
 * The SOURCE-OF-TRUTH orchestration layer: it stamps the residency-derived {@code domain} +
 * {@code createdBy} (never client-supplied), enforces the TOTAL-scope SUPERADMIN gate, allocates
 * the next version (the {@code maxVersion + 1} idiom), writes the set + per-service artifacts,
 * and hands off to the (dark) {@link BackupEffector}.
 *
 * <h3>Authorization model (fail-closed)</h3>
 * <ul>
 *   <li><b>domain from the validated issuer.</b> Every read/write is threaded a
 *       {@link PrincipalDomain} resolved from the cryptographically-validated JWT; a scoped ADMIN
 *       sees/writes ONLY their own brand's rows, a SUPERADMIN is unscoped. The set's
 *       {@code domain} is STAMPED from {@code scope.domain()}, never a body field, so a brand-X
 *       admin can never write a brand-Y row.</li>
 *   <li><b>owner == subject.</b> {@code createdBy} is the JWT subject the controller passes in
 *       (the acting principal), never a body field.</li>
 *   <li><b>TOTAL-scope is SUPERADMIN-only.</b> A scoped (non-superadmin) caller requesting a
 *       TOTAL backup is rejected here ({@link TotalScopeDeniedException} -> 403) as
 *       defence-in-depth behind the {@code /bff/superadmin/**} coarse gate + the per-method
 *       {@code @PreAuthorize("hasRole('SUPERADMIN')")} on the total endpoint.</li>
 *   <li><b>restore is step-up-gated.</b> The privileged restore requires a satisfied step-up
 *       (the controller checks {@link BackupStepUpGate} before calling
 *       {@link #restore}); this service additionally re-resolves the set IN SCOPE so a scoped
 *       admin can only restore their own brand's set.</li>
 * </ul>
 *
 * <h3>SHIPS DARK</h3>
 * The catalog rows are written, but the {@link BackupEffector} default is a Noop — no Velero
 * Job is emitted until the generator/Velero leg wires the real effector.
 */
// Explicit bean name to disambiguate from the legacy single-USB
// net.hugmesh.adminbff.backup.BackupService, which also derives the default
// short name "backupService". Both are @Service-scanned by the app component scan, so
// without distinct names the full application context fails to start with a
// ConflictingBeanDefinitionException. Every injection point wires these by TYPE
// (no by-name @Qualifier), so the explicit name is behaviorally inert.
@Service("cloudBackupService")
public class BackupService {

    private static final Logger log = LoggerFactory.getLogger(BackupService.class);

    private final BackupSetRepository sets;
    private final BackupArtifactRepository artifacts;
    private final BackupDestinationRepository destinations;
    private final RunningServiceProvider runningServices;
    private final BackupEffector effector;
    /** The transactional-outbox sink: a {@code backup-started} / {@code restore-started}
     *  notification_outbox row is written in the SAME reactive transaction as the
     *  backup_set effect, so the outbox row exists IFF the effect commits (the lossless
     *  transactional-outbox pattern SuspensionService established). SHIPS DARK — nothing
     *  DELIVERS the outbox row until a channel is enabled (the merged convention). */
    private final NotificationOutboxRepository outbox;
    /** Wraps the effect write(s) + the outbox write in ONE reactive transaction so the
     *  outbox row exists IFF the effect commits; a failure of either leg rolls BOTH back
     *  (the SuspensionService transactional-outbox idiom). */
    private final TransactionalOperator tx;

    public BackupService(BackupSetRepository sets, BackupArtifactRepository artifacts,
                         BackupDestinationRepository destinations,
                         RunningServiceProvider runningServices, BackupEffector effector,
                         NotificationOutboxRepository outbox, TransactionalOperator tx) {
        this.sets = sets;
        this.artifacts = artifacts;
        this.destinations = destinations;
        this.runningServices = runningServices;
        this.effector = effector;
        this.outbox = outbox;
        this.tx = tx;
    }

    // ── list (scoped) ────────────────────────────────────────────────────────────────────

    /** The backup sets VISIBLE to the caller (own brand; SUPERADMIN all). A SUPERADMIN may
     *  pass an explicit {@code filterDomain} to narrow the unscoped list to one brand; a
     *  scoped admin's {@code filterDomain} is IGNORED (they are already walled to their own
     *  brand — they can never widen or cross). */
    public Flux<BackupSet> list(PrincipalDomain scope, String filterDomain) {
        if (scope != null && !scope.scoped() && filterDomain != null && !filterDomain.isBlank()) {
            return sets.listForDomain(filterDomain.trim());
        }
        return sets.list(scope);
    }

    // ── create (stamp domain + owner; TOTAL = superadmin-only; allocate version) ──────────

    /**
     * Create a backup set. {@code scope} DOMAIN stamps the set with {@code scope.domain()};
     * scope TOTAL is rejected unless the caller is a SUPERADMIN. The version is allocated
     * MAX(version)+1 within the (stamped-domain, setKey). Per-service artifact rows are written
     * for each selected running service, then the (dark) effector is invoked.
     *
     * @param setKey   the logical backup identity (the version-chain key); blank -> a derived
     *                 default keyed on scope+domain.
     * @param scope    DOMAIN or TOTAL.
     * @param services the selected running services (the per-service menu); must be non-empty.
     * @param destKind destination kind; {@code destRef} the bucket/pool ref.
     * @param encryptionMeta a repo / age-recipient REFERENCE JSON (never the key); may be null.
     * @param createdBy the acting JWT subject (owner == subject).
     * @param domainScope the caller's validated tenant scope.
     */
    public Mono<BackupSet> create(String setKey, BackupCloudScope scope, List<String> services,
                                  BackupDestinationKind destKind, String destRef,
                                  String encryptionMeta, String createdBy, PrincipalDomain domainScope) {
        if (scope == null) {
            return Mono.error(new IllegalArgumentException("scope is required (DOMAIN or TOTAL)"));
        }
        if (services == null || services.isEmpty()) {
            return Mono.error(new IllegalArgumentException("at least one service is required"));
        }
        if (destKind == null || destRef == null || destRef.isBlank()) {
            return Mono.error(new IllegalArgumentException("a destination kind + ref is required"));
        }
        // TOTAL-scope is SUPERADMIN-only (defence-in-depth behind the controller gate).
        if (scope.isTotal() && (domainScope == null || domainScope.scoped())) {
            log.warn("[cloud-backup] DENY total-scope backup by non-superadmin (createdBy={})", createdBy);
            return Mono.error(new TotalScopeDeniedException(
                    "a total-cloud backup is restricted to superadmins"));
        }
        // domain stamped from the validated scope, never the caller's body.
        String domain = domainScope == null ? PrincipalDomain.NO_DOMAIN : domainScope.domain();
        String key = (setKey == null || setKey.isBlank())
                ? defaultSetKey(scope, domain) : setKey.trim();

        // Bump version then insert the set, artifacts, effector start, and outbox row transactionally.
        return sets.maxVersion(domain, key)
                .flatMap(maxV -> createVersionedBackupSet(key, maxV + 1, scope, domain,
                        createdBy, services, destKind, destRef, encryptionMeta));
    }

    /** Insert the backup set row, write its artifacts, start the effector, emit the outbox row,
     *  and commit all four writes together in a single reactive transaction. */
    private Mono<BackupSet> createVersionedBackupSet(
            String key, long version, BackupCloudScope scope, String domain, String createdBy,
            List<String> services, BackupDestinationKind destKind, String destRef,
            String encryptionMeta) {
        return sets.insert(key, version, scope, domain, createdBy, services, destKind, destRef,
                        encryptionMeta)
                .flatMap(set -> writeArtifacts(set, services).thenReturn(set))
                .flatMap(set -> effector.startBackup(set).thenReturn(set))
                // The per-domain @system notifications subsystem (notification_outbox 062)
                // writes an infra-event row in the SAME reactive transaction as the effect.
                .flatMap(set -> emitBackupStarted(set).thenReturn(set))
                .doOnNext(set -> log.info("[cloud-backup] created set id={} key={} v={} scope={} "
                                + "domain={} services={} by={}",
                        set.id(), key, version, scope, domain, services.size(), createdBy))
                // ── transaction boundary: the set + artifacts + outbox INSERTs commit together. ──
                .as(tx::transactional);
    }

    /**
     * Emit the {@code backup-started} outbox row for a just-created set in the SAME
     * reactive transaction as the effect (the lossless transactional-outbox pattern).
     * The {@code domain} is stamped from the EFFECT's domain (which came from the
     * validated scope, never a body field). The payload carries scope/version/service-
     * count/destination-kind ONLY — NEVER {@code createdBy} (the actor) or any
     * destination ref / encryption meta / key: the {@code @system} sender is neutral.
     *
     * <p>SHIPS DARK: the row is written but NOTHING DELIVERS it until a channel is
     * enabled — the same posture as every other {@code @system} event.
     */
    private Mono<Long> emitBackupStarted(BackupSet set) {
        return outbox.insert(
                set.domain(),
                NotificationOutbox.SOURCE_BACKUP_SET,
                set.id(),
                NotificationOutbox.CATEGORY_BACKUP_STARTED,
                // NOTE: no createdBy / actor, no destination ref / key — neutral @system payload.
                BackupNotificationPayload.build(set.scope().wire(), set.version(),
                        set.services() == null ? 0 : set.services().size(),
                        set.destinationKind() == null ? null : set.destinationKind().wire()));
    }

    private Mono<Void> writeArtifacts(BackupSet set, List<String> services) {
        return Flux.fromIterable(services)
                .filter(s -> s != null && !s.isBlank())
                .map(String::trim).distinct()
                .concatMap(service -> artifacts.insert(set.id(), service,
                        kindFor(service)))
                .then();
    }

    /** A reasonable default artifact kind for a service key when the menu did not carry one —
     *  postgres/casdoor/akkoma/phpbb are DB-backed (db_dump), secrets/config are config, the
     *  rest are pv_snapshot. The generator leg can refine this from the ConfigMap. */
    private static String kindFor(String service) {
        String s = service.toLowerCase();
        if (s.contains("postgres") || s.equals("casdoor") || s.equals("akkoma") || s.equals("phpbb")) {
            return BackupArtifact.KIND_DB_DUMP;
        }
        if (s.equals("secrets") || s.equals("config")) {
            return BackupArtifact.KIND_CONFIG;
        }
        return BackupArtifact.KIND_PV_SNAPSHOT;
    }

    private static String defaultSetKey(BackupCloudScope scope, String domain) {
        return scope.isTotal() ? "total-cloud" : ("domain-" + domain);
    }

    // ── versions (scoped) ────────────────────────────────────────────────────────────────

    /** The version history (chain) for the set's logical identity, scoped to the caller. */
    public Flux<BackupSet> versions(String id, PrincipalDomain scope) {
        return sets.versions(id, scope);
    }

    /** The per-service artifacts under a set, scoped to the caller via the set's scoped read
     *  (a scoped admin can only see their own brand's set's artifacts). */
    public Flux<BackupArtifact> artifacts(String id, PrincipalDomain scope) {
        return sets.findScoped(id, scope)
                .flatMapMany(set -> artifacts.listForSet(set.id()));
    }

    // ── restore (scoped re-resolve; step-up is checked in the controller) ─────────────────

    /**
     * Restore a backup set's version. The set is re-resolved IN SCOPE so a scoped admin can
     * ONLY restore their own brand's set (a cross-domain id is a clean 404 = not visible). The
     * STEP-UP requirement is enforced by the controller via {@link BackupStepUpGate} BEFORE
     * this is called; this method assumes step-up + role + domain have passed.
     */
    public Mono<BackupSet> restore(String id, String requestedBy, PrincipalDomain scope) {
        return sets.findScoped(id, scope)
                .switchIfEmpty(Mono.error(new IllegalArgumentException(
                        "backup set " + id + " not found in your scope")))
                // Start the restore effector + outbox row in a single reactive transaction.
                .flatMap(set -> startRestoreTransactionally(set, requestedBy));
    }

    /** Start the restore effector and emit the outbox row in a single reactive transaction. */
    private Mono<BackupSet> startRestoreTransactionally(BackupSet set, String requestedBy) {
        // Emit a 'restore-started' @system outbox row in the SAME reactive transaction
        // as the restore effect: the row exists IFF the restore effect commits.
        return effector.startRestore(set)
                .then(emitRestoreStarted(set))
                .thenReturn(set)
                .doOnNext(s -> log.info("[cloud-backup] restore requested set id={} v={} "
                                + "domain={} by={}", s.id(), s.version(), s.domain(), requestedBy))
                .as(tx::transactional);
    }

    /**
     * Emit the {@code restore-started} outbox row for a (step-up-gated) restore in the
     * SAME reactive transaction as the restore effect. The {@code domain} is the set's
     * stamped domain. The payload carries scope/version/service-count ONLY — NEVER
     * {@code requestedBy} (the actor): the {@code @system} sender is neutral. A restore
     * chooses no fresh destination, so {@code destination_kind} is omitted.
     *
     * <p>SHIPS DARK: written but NOTHING DELIVERS it until a channel is enabled.
     */
    private Mono<Long> emitRestoreStarted(BackupSet set) {
        return outbox.insert(
                set.domain(),
                NotificationOutbox.SOURCE_BACKUP_SET,
                set.id(),
                NotificationOutbox.CATEGORY_RESTORE_STARTED,
                // NOTE: no requestedBy / actor — neutral @system payload.
                BackupNotificationPayload.build(set.scope().wire(), set.version(),
                        set.services() == null ? 0 : set.services().size(), null));
    }

    // ── per-service backup menu (running services, scoped) ────────────────────────────────

    /** The running services available for the per-service backup menu, scoped to the caller. */
    public Flux<RunningService> services(PrincipalDomain scope) {
        return runningServices.runningServices(scope);
    }

    // ── destinations (scoped read; PUT stamps the domain) ────────────────────────────────

    /** The destination config for the caller's brand (a scoped admin) or an explicit brand (a
     *  superadmin passing {@code targetDomain}). Empty when unconfigured. */
    public Mono<BackupDestination> destination(PrincipalDomain scope, String targetDomain) {
        String domain = resolveDomainForDestination(scope, targetDomain);
        return destinations.findByDomain(domain);
    }

    /** Upsert the destination config for the caller's brand (a scoped admin) or an explicit
     *  brand (a superadmin passing {@code targetDomain}). The domain is STAMPED, never a body
     *  field. */
    public Mono<BackupDestination> putDestination(BackupDestinationKind kind, String destRef,
                                                  String secretRef, String updatedBy,
                                                  PrincipalDomain scope, String targetDomain) {
        if (kind == null || destRef == null || destRef.isBlank()) {
            return Mono.error(new IllegalArgumentException("a destination kind + ref is required"));
        }
        String domain = resolveDomainForDestination(scope, targetDomain);
        return destinations.upsert(kind, destRef, secretRef, domain, updatedBy)
                .doOnNext(d -> log.info("[cloud-backup] destination upsert domain={} kind={} by={}",
                        domain, kind.wire(), updatedBy));
    }

    /** A scoped admin's destination domain is ALWAYS their own brand ({@code targetDomain}
     *  ignored — they can't address another brand). A superadmin may target an explicit brand;
     *  absent one, the superadmin's home domain. */
    private static String resolveDomainForDestination(PrincipalDomain scope, String targetDomain) {
        if (scope == null) return PrincipalDomain.NO_DOMAIN;
        if (scope.scoped()) return scope.domain();
        return (targetDomain != null && !targetDomain.isBlank()) ? targetDomain.trim() : scope.domain();
    }

    /** A scoped (non-superadmin) caller asked for the SUPERADMIN-only total-cloud scope. */
    public static class TotalScopeDeniedException extends RuntimeException {
        public TotalScopeDeniedException(String message) {
            super(message);
        }
    }
}
