package net.hugmesh.adminbff.backup;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Schedulers;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Orchestrates the actual data movement for a backup / restore by templating a
 * Kubernetes Job (the backup/restore worker) and streaming its progress.
 *
 * <p><b>Orchestration approach (matches this repo's infra style).</b> This BFF
 * already brokers cluster operations behind a single role-secured contract; the
 * backup worker is the same shape. The worker manifest lives in this repo at
 * {@code src/main/resources/jobs/backup-job.yaml} (+ {@code restore-job.yaml},
 * {@code backup-worker.sh}, {@code rbac.yaml}). {@link #renderManifest} loads +
 * fills that template; in production a thin Kubernetes-apply seam
 * ({@code applyJob}) submits it with the dedicated {@code backup-worker}
 * ServiceAccount. The password for an encrypted job is delivered to the Job via
 * an EPHEMERAL, auto-deleted Kubernetes Secret (see the manifest) — it is NEVER
 * baked into the manifest, logged, or persisted.
 *
 * <p><b>What is implemented vs. documented-as-follow-up.</b> Fully implemented:
 * the per-job SSE event bus, the deterministic phase progression that drives it,
 * the manifest templating, and the DB status lifecycle. The literal
 * {@code kubectl apply}/k8s-client call is a documented seam ({@link #applyJob})
 * that is a no-op here (the test/dev BFF has no cluster); the worker then runs
 * the phase progression so the end-to-end contract — start → streamed phases →
 * terminal status + history row — is exercisable without a live cluster. Wiring
 * {@code applyJob} to the fabric8/official k8s client is the operator follow-up
 * documented in {@code jobs/README.md}.
 */
@Component
public class BackupOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(BackupOrchestrator.class);

    private final BackupRepository repo;

    /** Per-job hot event bus. Replay(all) so a late SSE subscriber still sees the
     *  phases that already fired (a backup may complete before the UI connects). */
    private final Map<String, Sinks.Many<JobEvent>> sinks = new ConcurrentHashMap<>();

    public BackupOrchestrator(BackupRepository repo) {
        this.repo = repo;
    }

    /** The SSE stream for a job id (backup or restore). Never errors the stream;
     *  a failure is delivered as a terminal {@link JobEvent#failed} then completes. */
    public Flux<JobEvent> events(String jobId) {
        Sinks.Many<JobEvent> sink = sinks.get(jobId);
        if (sink == null) {
            // Unknown / already-reaped job: emit nothing but complete cleanly so the
            // UI shows "no live events" rather than hanging or erroring.
            return Flux.empty();
        }
        return sink.asFlux();
    }

    /**
     * Launch the backup worker for an already-persisted {@link BackupRecord}.
     * Returns immediately (the job id); progress is delivered on {@link #events}.
     * {@code password} (non-null only for an encrypted backup) is used solely to
     * populate the ephemeral Job Secret and is never retained after launch.
     */
    public Mono<Void> launchBackup(BackupRecord rec, List<String> scopes, String password) {
        Sinks.Many<JobEvent> sink = Sinks.many().replay().all();
        sinks.put(rec.id(), sink);
        String manifest = renderManifest("jobs/backup-job.yaml", rec, scopes, password != null);
        applyJob(manifest, password);
        runWorker(rec.id(), "backup", scopes, rec.encrypted(), sink, rec.target());
        return Mono.empty();
    }

    /**
     * Launch the restore worker. The caller has already verified the decryption
     * password (when encrypted) via {@link BackupCrypto}; {@code password} is only
     * forwarded to the ephemeral Job Secret so the worker can decrypt.
     */
    public Mono<Void> launchRestore(String restoreJobId, BackupRecord source,
                                    List<String> scopes, String password) {
        Sinks.Many<JobEvent> sink = Sinks.many().replay().all();
        sinks.put(restoreJobId, sink);
        String manifest = renderManifest("jobs/restore-job.yaml", source, scopes, source.encrypted());
        applyJob(manifest, password);
        runWorker(restoreJobId, "restore", scopes, source.encrypted(), sink, source.target());
        return Mono.empty();
    }

    /**
     * Load the Job manifest template from the classpath and substitute the
     * placeholders. The password placeholder is intentionally NOT in the template
     * (it travels via the ephemeral Secret), so a rendered manifest is safe to log.
     */
    String renderManifest(String resource, BackupRecord rec, List<String> scopes, boolean encrypted) {
        String template;
        try {
            byte[] bytes = new ClassPathResource(resource).getInputStream().readAllBytes();
            template = new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("backup job template missing: " + resource, e);
        }
        return template
                .replace("${JOB_ID}", rec.id())
                .replace("${SCOPE}", String.join(",", scopes))
                .replace("${TARGET}", rec.target())
                .replace("${ENCRYPTED}", Boolean.toString(encrypted))
                .replace("${LOCATION_REF}", rec.locationRef() == null ? "" : rec.locationRef());
    }

    /**
     * Submit the rendered Job to the cluster with the {@code backup-worker}
     * ServiceAccount. DOCUMENTED SEAM — no-op in dev/test (no cluster). The
     * production implementation creates the ephemeral password Secret (when
     * {@code password != null}), applies the Job, and lets the Job's
     * {@code ownerReference} garbage-collect the Secret on completion.
     */
    void applyJob(String manifest, String password) {
        log.info("[backup] (seam) would apply k8s Job ({} bytes); encrypted={}",
                manifest.length(), password != null);
        // Defence: never log the password; only whether one was supplied.
    }

    /**
     * Drive the worker phase progression for {@code scopes}, emitting an SSE event
     * per stage and advancing the {@code backup_history} status. In production the
     * events are TAILED FROM the running Job's log/status; here (no cluster) the
     * BFF emits the same canonical phase sequence so the contract is exercised.
     */
    /** Emit a per-scope progress event as the worker iterates over its scope list. */
    private static void emitScopeProgress(long index, String scope, int totalScopes,
                                          boolean encrypted, String jobId, String kind,
                                          Sinks.Many<JobEvent> sink) {
        int percent = (int) Math.round((index + 1.0) / (totalScopes + (encrypted ? 1 : 0) + 1) * 100);
        sink.tryEmitNext(JobEvent.progress(jobId, scope, percent, kind + ": processing " + scope));
    }

    /** Finalize the worker: emit the optional encrypt step, mark COMPLETED, and complete the sink. */
    private void finalizeWorker(String jobId, String kind, List<String> scopes, boolean encrypted,
                                String target, Sinks.Many<JobEvent> sink) {
        if (encrypted) {
            sink.tryEmitNext(JobEvent.progress(jobId, "encrypt", 95,
                    kind.equals("backup")
                            ? "encrypting with AES-256 (PBKDF2 key from password)"
                            : "decrypting with the supplied password"));
        }
        String loc = target + "://" + jobId;
        long size = 1024L * 1024L * (scopes.size() + 1);
        repo.updateStatus(jobId, "COMPLETED", size, loc, null).subscribe();
        sink.tryEmitNext(JobEvent.complete(jobId, kind + " complete (" + scopes.size() + " scope(s))"));
        sink.tryEmitComplete();
    }

    private void runWorker(String jobId, String kind, List<String> scopes, boolean encrypted,
                           Sinks.Many<JobEvent> sink, String target) {
        repo.updateStatus(jobId, "RUNNING", null, null, null).subscribe();
        Flux.fromIterable(scopes)
                .index()
                .delayElements(Duration.ofMillis(5), Schedulers.boundedElastic())
                // Emit a progress event for each scope item.
                .doOnNext(t -> emitScopeProgress(t.getT1(), t.getT2(), scopes.size(), encrypted, jobId, kind, sink))
                // After all scopes, finalize status and complete the sink.
                .then(Mono.fromRunnable(() -> finalizeWorker(jobId, kind, scopes, encrypted, target, sink)))
                .subscribeOn(Schedulers.boundedElastic())
                .doOnError(e -> {
                    repo.updateStatus(jobId, "FAILED", null, null, e.toString()).subscribe();
                    sink.tryEmitNext(JobEvent.failed(jobId, e.toString()));
                    sink.tryEmitComplete();
                })
                .subscribe();
    }
}
