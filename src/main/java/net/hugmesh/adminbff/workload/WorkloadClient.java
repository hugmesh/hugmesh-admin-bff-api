package net.hugmesh.adminbff.workload;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.workload.WorkloadDtos.ExecResult;
import net.hugmesh.adminbff.workload.WorkloadDtos.LogLine;
import net.hugmesh.adminbff.workload.WorkloadDtos.NetworkSummary;
import net.hugmesh.adminbff.workload.WorkloadDtos.PodInspect;
import net.hugmesh.adminbff.workload.WorkloadDtos.PodMetrics;
import net.hugmesh.adminbff.workload.WorkloadDtos.PodSummary;
import net.hugmesh.adminbff.workload.WorkloadDtos.VolumeSummary;
import net.hugmesh.adminbff.workload.WorkloadDtos.WorkloadEvent;

import java.util.List;

/**
 * The k8s access SEAM for the workload console. EVERY caller (controllers, services) goes
 * through this interface; the two implementations are:
 *
 * <ul>
 *   <li>{@link NoopWorkloadClient} — the DEFAULT, fail-closed seam. Every read raises a
 *       {@link WorkloadClientException#unavailable} (mapped to 503, NEVER an empty 200); every
 *       mutate/stream/exec/port-forward raises unavailable too. A cluster-less dev/test/CI run
 *       and any deployment that has not flipped {@code app.workload-console.k8s.enabled=true}
 *       stays fully dark. This is what keeps the build green offline.</li>
 *   <li>{@code Fabric8WorkloadClient} — the real implementation, gated behind
 *       {@code app.workload-console.k8s.enabled=true}. Backed by the two least-privilege
 *       ServiceAccount tokens (read app-tier-only / mutate) the generator provisions; the
 *       superadmin cluster-wide read uses a separate SA. Errors fail-closed to
 *       {@link WorkloadClientException#failed} (502), never coerced to ALLOW.</li>
 * </ul>
 *
 * <p>The interface NEVER carries authorization — that is the central
 * {@link WorkloadAuthorizationFilter}'s sole responsibility (no controller is reachable
 * without it). The namespace-allowlist STEP 0b has ALSO already run before any {@code ns}
 * reaches a method here, so an implementation may trust the namespace it is handed is
 * app-tier; the read SA's RBAC is the in-cluster backstop.
 */
public interface WorkloadClient {

    /** True iff a real k8s client is wired (the controllers surface this on the capability
     *  probe; the Noop returns false). */
    boolean available();

    // ── READ (app-tier, via the read SA / superadmin cluster-read SA) ───────────

    Flux<PodSummary> listPods(String namespace);

    /** All pods cluster-wide across the app-tier allowlist (superadmin only — the caller has
     *  already constrained the namespace set to the allowlist). */
    Flux<PodSummary> listPodsAll(List<String> namespaces);

    Mono<PodInspect> inspectPod(String namespace, String name);

    /** The namespace's owner-chain domain attribution — the {@code hugmesh.net/domain}
     *  label the generator stamps on the namespace via the ArgoCD owner chain (the STEP-7
     *  per-tenant cut for the namespace-wide reads: metrics/events/volumes/network). Emits the
     *  label value, or EMPTY when the namespace carries none (the single-brand-cluster default,
     *  treated as the brand's own by {@code WorkloadReadService}). NEVER a forgeable pod-applied
     *  label — read from the namespace object itself. */
    Mono<String> namespaceDomain(String namespace);

    Flux<PodMetrics> podMetrics(String namespace);

    Flux<WorkloadEvent> events(String namespace);

    Flux<VolumeSummary> volumes(String namespace);

    Flux<NetworkSummary> network(String namespace);

    /** A bounded, redacted, NON-stream log read (the admin log_access path + the superadmin
     *  history fallback). The {@code redactor} is applied by the service, not here. */
    Mono<String> readLog(String namespace, String pod, String container, int tailLines);

    // ── DANGEROUS read-stream (superadmin only, dangerous-tier-gated) ───────────

    /** The live log-tail (logs -f). Emits a {@link LogLine} per line; the service redacts
     *  each line and re-authorizes per heartbeat. */
    Flux<LogLine> streamLog(String namespace, String pod, String container);

    // ── RUNTIME_MUTATE (superadmin only, via the mutate SA) ─────────────────────

    /** Delete a pod (the runtime-ephemeral restart / kill-recreate; the controller recreates
     *  it — selfHeal-neutral). Returns the deleted pod name(s) count. */
    Mono<Integer> deletePod(String namespace, String pod);

    /** Delete every pod of a workload (rollout-restart = delete the pods). */
    Mono<Integer> deleteWorkloadPods(String namespace, String workload);

    // ── DANGEROUS exec (superadmin only, step-up + Lease + device-license) ──────

    /** A one-shot read-only exec (non-TTY). The command has already been validated against
     *  the read-only allowlist by the service. */
    Mono<ExecResult> execReadOnly(String namespace, String pod, String container, List<String> command);

    /** Open an interactive TTY exec session (exec -it). The returned session bridges the
     *  duplex byte stream to the WS handler. */
    Mono<ExecSession> openExec(String namespace, String pod, String container, List<String> command);

    /** Force a reschedule of the pod after an exec session closes (the detection-gap
     *  quarantine — pod-delete so the controller recreates a clean pod). */
    Mono<Void> rescheduleAfterExec(String namespace, String pod);

    // ── DANGEROUS port-forward (superadmin only, curated allowlist) ─────────────

    /** Open a curated port-forward. The (ns, workload, port) has already been checked against
     *  the curated allowlist + a per-open device/SSH-license by the service. */
    Mono<PortForwardSession> openPortForward(String namespace, String workload, int port);

    /** An interactive TTY exec session bridged to the WS handler. */
    interface ExecSession {
        /** Push a chunk of stdin bytes to the container's TTY. */
        void writeStdin(byte[] data);

        /** Resize the TTY (cols, rows). */
        void resize(int cols, int rows);

        /** The merged stdout/stderr byte stream from the container's TTY. */
        Flux<byte[]> output();

        /** Close the session (and trigger the after-close reschedule via the service). */
        void close();
    }

    /** A live curated port-forward session. */
    interface PortForwardSession {
        /** The local proxy port the BFF bound for this forward. */
        int localPort();

        void close();
    }
}
