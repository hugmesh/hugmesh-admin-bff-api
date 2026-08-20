package net.hugmesh.adminbff.inference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.notification.FeatureNotificationService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * AIOps: turn a batch of mesh infra / security signals into an admin-facing Matrix
 * {@code @system} alert via the edge-AI node, REUSING the existing notifications
 * subsystem end-to-end:
 *
 * <pre>
 *   signals ──▶ {@link EdgeAiInferenceClient#triageInfra} ──▶ {@link FeatureNotificationService}
 *               (GPU edge-AI triage)          (INFRA_IMPACTING outbox row, per admin)
 *                                                      │
 *                                                      ▼  ExternalChannelReconciler (existing)
 *                                              Matrix @system DM to each admin/superadmin
 * </pre>
 *
 * <p>The signal COLLECTION side (a node/DaemonSet collector tailing Snort/Suricata + AIDE +
 * k8s events) is a separate, node-level concern; this service is the triage→notify producer
 * that such a collector (or a scheduled reconciler) drives by handing it the raw signals plus
 * the admin recipient subjects for the tenant.
 *
 * <p>Ships DARK with the edge-AI client: when {@code inference.edge-ai.enabled=false} (default)
 * the triage is a {@code disabled} sentinel and NO notification is emitted, so a mesh without a
 * GPU/edge-AI node is unaffected. Idempotent: the per-admin outbox natural key is DERIVED from
 * the {@code eventKey} (see {@link #outboxKey}), so a retried signal produces no duplicate alert.
 */
@Service
public class AioTriageService {

    private static final Logger log = LoggerFactory.getLogger(AioTriageService.class);

    /** Width of {@code notification_outbox.source_id} (changeset 062) — the hard ceiling
     *  {@link #outboxKey} derives the per-admin natural key to fit. Must stay EVEN: the
     *  derivation appends whole hex-encoded BYTES, so an odd ceiling would overshoot it. */
    private static final int SOURCE_ID_MAX = 36;

    private final EdgeAiInferenceClient edgeAi;
    private final FeatureNotificationService notifications;

    public AioTriageService(EdgeAiInferenceClient edgeAi, FeatureNotificationService notifications) {
        this.edgeAi = edgeAi;
        this.notifications = notifications;
    }

    /**
     * Triage {@code signals} on the edge-AI node and, IFF a real verdict is produced, emit one
     * {@code infra-impacting} notification per admin recipient (the reconciler delivers them as
     * Matrix {@code @system} DMs). Fail-open: a disabled/degraded edge-AI yields no alert rather
     * than an error, so a stalled inference node never blocks the collector.
     *
     * @param domain        the validated tenant (never user-settable)
     * @param adminSubjects the admin/superadmin Casdoor subjects to alert (recipient resolution
     *                      is the caller's RBAC concern — this service never widens the audience)
     * @param eventKey      a stable key for this signal batch (the per-admin outbox natural key
     *                      is derived from it → idempotent)
     * @param signals       the raw infra/NIDS/integrity/k8s signal text
     * @return the number of admins newly alerted (deduped retries count 0)
     */
    public Mono<Long> triageAndNotify(String domain, List<String> adminSubjects,
                                      String eventKey, String signals) {
        if (domain == null || domain.isBlank()) {
            return Mono.error(new IllegalArgumentException("domain is required"));
        }
        if (adminSubjects == null || adminSubjects.isEmpty()) {
            return Mono.error(new IllegalArgumentException("at least one admin recipient is required"));
        }
        return edgeAi.triageInfra(signals)
                .flatMap(triage -> alertAdminsOnTriage(domain, adminSubjects, eventKey, triage));
    }

    /**
     * Apply one edge-AI {@code triage} verdict: when the verdict is unavailable (disabled/degraded)
     * emit no alert (fail-open, returns 0); otherwise fan out one {@code INFRA_IMPACTING}
     * notification per admin recipient and count the newly-alerted admins. Extracted from the
     * {@code flatMap} lambda to keep the reactive operator body short and named.
     */
    private Mono<Long> alertAdminsOnTriage(String domain, List<String> adminSubjects,
                                           String eventKey, TriageResult triage) {
        if (!triage.available()) {
            log.info("[aio] edge-AI triage unavailable ({}) — no admin alert emitted for key={}",
                    triage.summary(), eventKey);
            return Mono.just(0L);
        }
        log.info("[aio] triage severity={} key={} → alerting {} admin(s)",
                triage.severity(), eventKey, adminSubjects.size());
        return Flux.fromIterable(adminSubjects)
                .flatMap(admin -> notifications.emit(
                        FeatureNotificationService.Kind.INFRA_IMPACTING,
                        domain, admin, outboxKey(eventKey, admin), triage.asNote()))
                .filter(Boolean::booleanValue)
                .count();
    }

    /**
     * The per-admin outbox natural key, DERIVED rather than concatenated.
     * {@code notification_outbox.source_id} is {@code varchar(36)} (changeset 062), so the
     * literal {@code eventKey + ":" + admin} pair overflows the column for any realistic
     * Casdoor subject ({@code "snort:rule-123" + ":" + "google:admin@example.org"} is already
     * 40 characters). MEASURED on the repo's H2 test store: the INSERT fails outright
     * ({@code BadSqlGrammar}), so the alert is lost and the caller gets an error it cannot act
     * on. Worse where the driver reports the overflow as a data-integrity violation instead
     * (the Postgres {@code 22001} mapping): {@code NotificationOutboxRepository#insertIfAbsent}
     * classifies THAT as the natural-key DUPLICATE it exists to swallow, so the alert is
     * dropped silently and reported as {@code 0} newly-alerted admins. Since nothing has ever
     * called this service (that is the gap the ingest controller closes), no key of the old
     * shape exists to be compatible with.
     *
     * <p>{@code sha256(eventKey + ":" + admin)} truncated to 36 lowercase hex characters keeps
     * both properties the concatenation was there for — the SAME pair always derives the SAME
     * key (a retried signal batch still dedups to one alert per admin), and different admins
     * derive different keys (the per-recipient fan-out is preserved) — while always fitting
     * the column. The 12-hex {@code HeadscaleAclCompiler#hash12} precedent, widened to the
     * full column.
     */
    private static String outboxKey(String eventKey, String admin) {
        byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256")
                    .digest((eventKey + ":" + admin).getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is a mandated platform algorithm; unreachable.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        StringBuilder hex = new StringBuilder(SOURCE_ID_MAX);
        for (int i = 0; hex.length() < SOURCE_ID_MAX; i++) {
            hex.append(Character.forDigit((digest[i] >> 4) & 0xF, 16));
            hex.append(Character.forDigit(digest[i] & 0xF, 16));
        }
        return hex.toString();
    }
}
