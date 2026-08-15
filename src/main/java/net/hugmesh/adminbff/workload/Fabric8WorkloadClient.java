package net.hugmesh.adminbff.workload;

import io.fabric8.kubernetes.api.model.Container;
import io.fabric8.kubernetes.api.model.ContainerStatus;
import io.fabric8.kubernetes.api.model.OwnerReference;
import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.LocalPortForward;
import io.fabric8.kubernetes.client.dsl.ExecListener;
import io.fabric8.kubernetes.client.dsl.ExecWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.workload.WorkloadDtos.ContainerSummary;
import net.hugmesh.adminbff.workload.WorkloadDtos.ExecResult;
import net.hugmesh.adminbff.workload.WorkloadDtos.LogLine;
import net.hugmesh.adminbff.workload.WorkloadDtos.NetworkSummary;
import net.hugmesh.adminbff.workload.WorkloadDtos.PodInspect;
import net.hugmesh.adminbff.workload.WorkloadDtos.PodMetrics;
import net.hugmesh.adminbff.workload.WorkloadDtos.PodSummary;
import net.hugmesh.adminbff.workload.WorkloadDtos.VolumeSummary;
import net.hugmesh.adminbff.workload.WorkloadDtos.WorkloadEvent;

import java.io.ByteArrayOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The REAL {@link WorkloadClient}, backed by TWO fabric8 {@link KubernetesClient}s — one per
 * least-privilege ServiceAccount the generator provisions (workload-console-rbac):
 *
 * <ul>
 *   <li>{@code readClient} (workload-console-read SA) — every read: list/inspect/
 *       namespace-domain/metrics/events/volumes/network/logs. Its Role has NO
 *       exec/portforward/delete/secrets;</li>
 *   <li>{@code mutateClient} (workload-console-mutate SA) — every runtime mutation:
 *       delete/rollout-restart/exec/port-forward (pods delete + pods/exec + pods/portforward
 *       create, nothing wider).</li>
 * </ul>
 *
 * Either half may be ABSENT (its projected token file was not mounted): that half then raises
 * {@link WorkloadClientException#unavailable} on every call — the SAME 503 posture as the
 * {@link NoopWorkloadClient}, NEVER a fallback onto the other half or the pod's own SA (the
 * pod runs as backups-effector; see {@link WorkloadConsoleClientConfig}). Wired ONLY when
 * {@code app.workload-console.k8s.enabled=true} — otherwise the fail-closed
 * {@link NoopWorkloadClient} is the bean. Every blocking fabric8 call is wrapped on the
 * boundedElastic scheduler (the reactive boundary), and EVERY error fails-closed to
 * {@link WorkloadClientException#failed} (mapped to 502), never coerced to an empty success.
 *
 * <p>The namespace allowlist (STEP 0b) + the central authz predicate have already run before
 * any call reaches here, and the in-cluster RBAC of the two least-privilege ServiceAccounts
 * is the defence-in-depth backstop (bound ONLY in app-tier namespaces).
 */
public class Fabric8WorkloadClient implements WorkloadClient {

    private static final Logger log = LoggerFactory.getLogger(Fabric8WorkloadClient.class);

    static final String READ_DARK_MSG =
            "workload console READ k8s client is not available "
            + "(workload-console-read SA token not mounted) — fail-closed";
    static final String MUTATE_DARK_MSG =
            "workload console MUTATE k8s client is not available "
            + "(workload-console-mutate SA token not mounted) — fail-closed";

    private final KubernetesClient readClient;
    private final KubernetesClient mutateClient;

    /** Either half may be null (its SA token file was absent) — that half then 503s. */
    public Fabric8WorkloadClient(KubernetesClient readClient, KubernetesClient mutateClient) {
        this.readClient = readClient;
        this.mutateClient = mutateClient;
    }

    @Override
    public boolean available() {
        return readClient != null || mutateClient != null;
    }

    boolean readHalfAvailable() {
        return readClient != null;
    }

    boolean mutateHalfAvailable() {
        return mutateClient != null;
    }

    /** The read half, or the Noop/503 posture when its SA token was never mounted. Called
     *  INSIDE the reactive callables so the dark half surfaces as an error signal, not a
     *  synchronous throw at assembly. */
    private KubernetesClient read() {
        if (readClient == null) throw WorkloadClientException.unavailable(READ_DARK_MSG);
        return readClient;
    }

    /** The mutate half, or the Noop/503 posture when its SA token was never mounted. */
    private KubernetesClient mutate() {
        if (mutateClient == null) throw WorkloadClientException.unavailable(MUTATE_DARK_MSG);
        return mutateClient;
    }

    /** Wrap a k8s failure as a 502 — but PRESERVE a fail-closed 503 riding the cause chain
     *  (a projected token vanishing mid-flight raises unavailable inside the fabric8 request
     *  pipeline, which may hand it back wrapped). */
    private static WorkloadClientException fail(String what, Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof WorkloadClientException w && w.isUnavailable()) return w;
        }
        return WorkloadClientException.failed("workload k8s call failed: " + what, t);
    }

    // ── projections ─────────────────────────────────────────────────────────────

    private static String workloadOf(Pod p) {
        List<OwnerReference> owners = p.getMetadata() == null ? null : p.getMetadata().getOwnerReferences();
        if (owners != null && !owners.isEmpty()) {
            return owners.get(0).getName();
        }
        return p.getMetadata() == null ? null : p.getMetadata().getName();
    }

    private static List<ContainerSummary> containers(Pod p) {
        List<ContainerSummary> out = new ArrayList<>();
        List<ContainerStatus> statuses = p.getStatus() == null ? List.of()
                : Optional.ofNullable(p.getStatus().getContainerStatuses()).orElse(List.of());
        Map<String, ContainerStatus> byName = new LinkedHashMap<>();
        for (ContainerStatus cs : statuses) {
            byName.put(cs.getName(), cs);
        }
        List<Container> specs = p.getSpec() == null ? List.of()
                : Optional.ofNullable(p.getSpec().getContainers()).orElse(List.of());
        for (Container c : specs) {
            ContainerStatus cs = byName.get(c.getName());
            boolean ready = cs != null && Boolean.TRUE.equals(cs.getReady());
            int restarts = cs != null && cs.getRestartCount() != null ? cs.getRestartCount() : 0;
            String state = "unknown";
            if (cs != null && cs.getState() != null) {
                if (cs.getState().getRunning() != null) state = "running";
                else if (cs.getState().getWaiting() != null) state = "waiting";
                else if (cs.getState().getTerminated() != null) state = "terminated";
            }
            out.add(new ContainerSummary(c.getName(), c.getImage(), ready, restarts, state));
        }
        return out;
    }

    private static int totalRestarts(Pod p) {
        int n = 0;
        if (p.getStatus() != null && p.getStatus().getContainerStatuses() != null) {
            for (ContainerStatus cs : p.getStatus().getContainerStatuses()) {
                n += cs.getRestartCount() == null ? 0 : cs.getRestartCount();
            }
        }
        return n;
    }

    private static PodSummary summary(Pod p) {
        var meta = p.getMetadata();
        var status = p.getStatus();
        boolean ready = status != null && status.getConditions() != null
                && status.getConditions().stream()
                .anyMatch(c -> "Ready".equals(c.getType()) && "True".equals(c.getStatus()));
        return new PodSummary(
                meta == null ? null : meta.getNamespace(),
                meta == null ? null : meta.getName(),
                workloadOf(p),
                status == null ? null : status.getPhase(),
                ready,
                totalRestarts(p),
                p.getSpec() == null ? null : p.getSpec().getNodeName(),
                parseTs(status == null ? null : status.getStartTime()),
                containers(p));
    }

    private static Instant parseTs(String t) {
        try {
            return t == null ? null : Instant.parse(t);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public Flux<PodSummary> listPods(String namespace) {
        return Mono.fromCallable(() ->
                        read().pods().inNamespace(namespace).list().getItems().stream()
                                .map(Fabric8WorkloadClient::summary).toList())
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable)
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("listPods " + namespace, t));
    }

    @Override
    public Flux<PodSummary> listPodsAll(List<String> namespaces) {
        return Flux.fromIterable(namespaces).flatMap(this::listPods);
    }

    @Override
    public Mono<PodInspect> inspectPod(String namespace, String name) {
        // Fetch and project the pod metadata on boundedElastic (blocking k8s call).
        return Mono.fromCallable(() -> fetchPodInspect(read(), namespace, name))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("inspectPod " + name, t));
    }

    /** Blocking: fetch the pod and project to a PodInspect (labels only, no secrets). */
    private static PodInspect fetchPodInspect(KubernetesClient client, String namespace, String name) {
        Pod p = client.pods().inNamespace(namespace).withName(name).get();
        if (p == null) return null;
        var meta = p.getMetadata();
        var status = p.getStatus();
        String ownerKind = null, ownerName = null;
        if (meta != null && meta.getOwnerReferences() != null && !meta.getOwnerReferences().isEmpty()) {
            ownerKind = meta.getOwnerReferences().get(0).getKind();
            ownerName = meta.getOwnerReferences().get(0).getName();
        }
        // PROJECTION: labels only, NO annotations / managedFields / env.
        return new PodInspect(
                meta == null ? null : meta.getNamespace(),
                meta == null ? null : meta.getName(),
                workloadOf(p),
                status == null ? null : status.getPhase(),
                p.getSpec() == null ? null : p.getSpec().getNodeName(),
                p.getSpec() == null ? null : p.getSpec().getServiceAccountName(),
                parseTs(status == null ? null : status.getStartTime()),
                containers(p),
                meta == null || meta.getLabels() == null ? Map.of() : meta.getLabels(),
                ownerKind, ownerName);
    }

    @Override
    public Mono<String> namespaceDomain(String namespace) {
        // Read the namespace object's owner-chain domain label on boundedElastic (blocking get).
        // EMPTY when the namespace is unlabelled (single-brand-cluster default) or absent.
        return Mono.fromCallable(() -> fetchNamespaceDomain(read(), namespace))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(opt -> opt.map(Mono::just).orElseGet(Mono::empty))
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("namespaceDomain " + namespace, t));
    }

    /** Blocking: read the namespace's {@code hugmesh.systems/domain} owner-chain label;
     *  Optional.empty when the namespace has no such label (or does not exist). */
    private static Optional<String> fetchNamespaceDomain(KubernetesClient client, String namespace) {
        var ns = client.namespaces().withName(namespace).get();
        if (ns == null || ns.getMetadata() == null || ns.getMetadata().getLabels() == null) {
            return Optional.empty();
        }
        String domain = ns.getMetadata().getLabels().get(WorkloadReadService.DOMAIN_LABEL);
        return domain == null || domain.isBlank() ? Optional.empty() : Optional.of(domain);
    }

    @Override
    public Flux<PodMetrics> podMetrics(String namespace) {
        // Collect pod metrics on boundedElastic; swallow absence (metrics-server optional).
        // read() is resolved OUTSIDE the helper's swallow-catch so a dark read half stays 503.
        return Mono.fromCallable(() -> fetchPodMetrics(read(), namespace))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    /** Blocking: collect per-pod cpu/mem metrics; returns empty list when metrics-server is absent. */
    private static List<PodMetrics> fetchPodMetrics(KubernetesClient client, String namespace) {
        List<PodMetrics> out = new ArrayList<>();
        try {
            client.top().pods().metrics(namespace).getItems().forEach(m -> {
                String cpu = "", mem = "";
                if (m.getContainers() != null && !m.getContainers().isEmpty()
                        && m.getContainers().get(0).getUsage() != null) {
                    var usage = m.getContainers().get(0).getUsage();
                    cpu = usage.containsKey("cpu") ? usage.get("cpu").toString() : "";
                    mem = usage.containsKey("memory") ? usage.get("memory").toString() : "";
                }
                out.add(new PodMetrics(namespace, m.getMetadata().getName(), cpu, mem));
            });
        } catch (Exception e) {
            // metrics-server may be absent; surface empty metrics rather than 502
            log.debug("[workload] metrics unavailable for {}: {}", namespace, e.toString());
        }
        return out;
    }

    @Override
    public Flux<WorkloadEvent> events(String namespace) {
        // Map k8s Event objects to WorkloadEvent on boundedElastic (blocking list call).
        return Mono.fromCallable(() ->
                        read().v1().events().inNamespace(namespace).list().getItems().stream()
                                .map(e -> toWorkloadEvent(namespace, e)).toList())
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable)
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("events " + namespace, t));
    }

    /** Project a k8s Event into a WorkloadEvent (namespace, type, reason, object, message, time, count). */
    private WorkloadEvent toWorkloadEvent(String namespace, io.fabric8.kubernetes.api.model.Event e) {
        return new WorkloadEvent(namespace, e.getType(), e.getReason(),
                e.getInvolvedObject() == null ? null
                        : e.getInvolvedObject().getKind() + "/" + e.getInvolvedObject().getName(),
                e.getMessage(), parseTs(e.getLastTimestamp()),
                e.getCount() == null ? 0 : e.getCount());
    }

    @Override
    public Flux<VolumeSummary> volumes(String namespace) {
        // Map PVC resources to VolumeSummary on boundedElastic (blocking list call).
        return Mono.fromCallable(() ->
                        read().persistentVolumeClaims().inNamespace(namespace).list().getItems().stream()
                                .map(pvc -> toVolumeSummary(namespace, pvc)).toList())
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable)
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("volumes " + namespace, t));
    }

    /** Project a k8s PersistentVolumeClaim to a VolumeSummary. */
    private static VolumeSummary toVolumeSummary(String namespace,
                                                  io.fabric8.kubernetes.api.model.PersistentVolumeClaim pvc) {
        return new VolumeSummary(namespace,
                pvc.getMetadata().getName(),
                pvc.getStatus() == null ? null : pvc.getStatus().getPhase(),
                pvc.getStatus() == null || pvc.getStatus().getCapacity() == null
                        ? null : String.valueOf(pvc.getStatus().getCapacity().get("storage")),
                pvc.getSpec() == null ? null : pvc.getSpec().getStorageClassName(),
                pvc.getSpec() == null || pvc.getSpec().getAccessModes() == null
                        ? List.of() : pvc.getSpec().getAccessModes());
    }

    @Override
    public Flux<NetworkSummary> network(String namespace) {
        return Mono.fromCallable(() -> {
                    KubernetesClient client = read();
                    List<NetworkSummary> out = new ArrayList<>();
                    client.services().inNamespace(namespace).list().getItems().forEach(s ->
                            out.add(new NetworkSummary(namespace, "Service", s.getMetadata().getName(),
                                    s.getSpec() == null ? "" : String.valueOf(s.getSpec().getType()))));
                    client.network().networkPolicies().inNamespace(namespace).list().getItems().forEach(np ->
                            out.add(new NetworkSummary(namespace, "NetworkPolicy",
                                    np.getMetadata().getName(), "")));
                    return out;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable)
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("network " + namespace, t));
    }

    @Override
    public Mono<String> readLog(String namespace, String pod, String container, int tailLines) {
        return Mono.fromCallable(() ->
                        read().pods().inNamespace(namespace).withName(pod).inContainer(container)
                                .tailingLines(Math.max(1, tailLines)).getLog())
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("readLog " + pod, t));
    }

    @Override
    public Flux<LogLine> streamLog(String namespace, String pod, String container) {
        // Open the log watch then drain it line-by-line on boundedElastic.
        return Flux.<LogLine>create(sink -> openLogStream(namespace, pod, container, sink))
                .subscribeOn(Schedulers.boundedElastic());
    }

    /** Open a piped log watch and drain lines to the sink on boundedElastic; dispose closes
     *  the watch. A dark read half surfaces via {@code fail}'s unavailable-preserving unwrap. */
    private void openLogStream(String namespace, String pod, String container,
                                reactor.core.publisher.FluxSink<LogLine> sink) {
        PipedOutputStream pos = new PipedOutputStream();
        try {
            PipedInputStream pis = new PipedInputStream(pos, 64 * 1024);
            var watch = read().pods().inNamespace(namespace).withName(pod)
                    .inContainer(container).watchLog(pos);
            Schedulers.boundedElastic().schedule(() -> drainLogLines(pis, container, pod, sink));
            sink.onDispose(() -> {
                try {
                    watch.close();
                } catch (Exception ignore) { //NOPMD EmptyCatchBlock - best-effort close
                }
            });
        } catch (Exception e) {
            sink.error(fail("streamLog open " + pod, e));
        }
    }

    /** Blocking: read log lines from the piped stream and emit them to the sink until EOF or error. */
    private void drainLogLines(PipedInputStream pis, String container, String pod,
                                reactor.core.publisher.FluxSink<LogLine> sink) {
        try (var reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(pis, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sink.next(new LogLine(container, line, Instant.now()));
            }
            sink.complete();
        } catch (Exception e) {
            sink.error(fail("streamLog read " + pod, e));
        }
    }

    @Override
    public Mono<Integer> deletePod(String namespace, String pod) {
        return Mono.fromCallable(() -> {
                    var details = mutate().pods().inNamespace(namespace).withName(pod).delete();
                    return details == null ? 0 : details.size();
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("deletePod " + pod, t));
    }

    @Override
    public Mono<Integer> deleteWorkloadPods(String namespace, String workload) {
        // List pods matching the workload label then delete each on boundedElastic.
        return Mono.fromCallable(() -> deleteMatchingPods(mutate(), namespace, workload))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("deleteWorkloadPods " + workload, t));
    }

    /** Blocking: delete all pods whose workload label matches and return the total deleted count. */
    private static int deleteMatchingPods(KubernetesClient client, String namespace, String workload) {
        var pods = client.pods().inNamespace(namespace).list().getItems().stream()
                .filter(p -> workload.equals(workloadOf(p)))
                .map(p -> p.getMetadata().getName()).toList();
        int n = 0;
        for (String name : pods) {
            var d = client.pods().inNamespace(namespace).withName(name).delete();
            n += d == null ? 0 : d.size();
        }
        return n;
    }

    @Override
    public Mono<ExecResult> execReadOnly(String namespace, String pod, String container,
                                         List<String> command) {
        // Run the one-shot exec on boundedElastic (blocks until the command exits). Exec is a
        // pods/exec CREATE — the MUTATE SA's verb (the read Role has no exec), even read-only.
        return Mono.fromCallable(() -> runExecReadOnly(mutate(), namespace, pod, container, command))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("execReadOnly " + pod, t));
    }

    /** Blocking: exec a read-only command, capture stdout+stderr, return exit code + output. */
    private static ExecResult runExecReadOnly(KubernetesClient client, String namespace, String pod,
                                        String container, List<String> command) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        final int[] exit = {-1};
        try (ExecWatch watch = client.pods().inNamespace(namespace).withName(pod)
                .inContainer(container).writingOutput(out).writingError(err)
                .usingListener(new ExecListener() {
                    @Override
                    public void onClose(int code, String reason) {
                        exit[0] = code;
                    }
                })
                .exec(command.toArray(new String[0]))) {
            watch.exitCode().get(); // block until close
        }
        return new ExecResult(exit[0], out.toString(StandardCharsets.UTF_8),
                err.toString(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<ExecSession> openExec(String namespace, String pod, String container,
                                      List<String> command) {
        // Open a PTY exec session on boundedElastic (blocking k8s watch setup).
        return Mono.fromCallable(() -> openExecSession(mutate(), namespace, pod, container, command))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("openExec " + pod, t));
    }

    /** Blocking: wire piped stdin + sink-backed stdout/stderr and open the PTY exec watch. */
    private static ExecSession openExecSession(KubernetesClient client, String namespace, String pod,
                                         String container, List<String> command) throws Exception {
        Sinks.Many<byte[]> output = Sinks.many().multicast().onBackpressureBuffer();
        PipedInputStream stdin = new PipedInputStream(64 * 1024);
        PipedOutputStream stdinWriter = new PipedOutputStream(stdin);
        ExecWatch watch = client.pods().inNamespace(namespace).withName(pod)
                .inContainer(container).readingInput(stdin)
                .writingOutput(new SinkOutputStream(output))
                .writingError(new SinkOutputStream(output))
                .withTTY().exec(command.toArray(new String[0]));
        return new Fabric8ExecSession(watch, output, stdinWriter);
    }

    @Override
    public Mono<Void> rescheduleAfterExec(String namespace, String pod) {
        return deletePod(namespace, pod).then();
    }

    @Override
    public Mono<PortForwardSession> openPortForward(String namespace, String workload, int port) {
        // Resolve the first pod of the workload then open a port-forward on boundedElastic.
        return Mono.fromCallable(() -> openPortForwardSession(mutate(), namespace, workload, port))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(t -> !(t instanceof WorkloadClientException), t -> fail("openPortForward " + workload, t));
    }

    /** Blocking: find the first pod of the workload and open a LocalPortForward to it. */
    private static PortForwardSession openPortForwardSession(KubernetesClient client, String namespace,
                                                       String workload, int port) {
        // Forward to the first ready pod of the workload.
        String podName = client.pods().inNamespace(namespace).list().getItems().stream()
                .filter(p -> workload.equals(workloadOf(p)))
                .map(p -> p.getMetadata().getName())
                .findFirst()
                .orElseThrow(() -> fail("portForward no pod for " + workload, null));
        LocalPortForward fwd = client.pods().inNamespace(namespace).withName(podName).portForward(port);
        return new Fabric8PortForwardSession(fwd);
    }

    // ── session bridges ─────────────────────────────────────────────────────────

    private static final class SinkOutputStream extends java.io.OutputStream {
        private final Sinks.Many<byte[]> sink;

        SinkOutputStream(Sinks.Many<byte[]> sink) {
            this.sink = sink;
        }

        @Override
        public void write(int b) {
            sink.tryEmitNext(new byte[]{(byte) b});
        }

        @Override
        public void write(byte[] b, int off, int len) {
            byte[] copy = new byte[len];
            System.arraycopy(b, off, copy, 0, len);
            sink.tryEmitNext(copy);
        }
    }

    private static final class Fabric8ExecSession implements ExecSession {
        private final ExecWatch watch;
        private final Sinks.Many<byte[]> output;
        private final PipedOutputStream stdin;

        Fabric8ExecSession(ExecWatch watch, Sinks.Many<byte[]> output, PipedOutputStream stdin) {
            this.watch = watch;
            this.output = output;
            this.stdin = stdin;
        }

        @Override
        public void writeStdin(byte[] data) {
            try {
                stdin.write(data);
                stdin.flush();
            } catch (Exception e) {
                log.debug("[workload] exec stdin write failed: {}", e.toString());
            }
        }

        @Override
        public void resize(int cols, int rows) {
            try {
                watch.resize(cols, rows);
            } catch (Exception e) {
                log.debug("[workload] exec resize failed: {}", e.toString());
            }
        }

        @Override
        public Flux<byte[]> output() {
            return output.asFlux();
        }

        @Override
        public void close() {
            try {
                stdin.close();
            } catch (Exception ignore) { //NOPMD EmptyCatchBlock - best-effort teardown
            }
            try {
                watch.close();
            } catch (Exception ignore) { //NOPMD EmptyCatchBlock - best-effort teardown
            }
            output.tryEmitComplete();
        }
    }

    private static final class Fabric8PortForwardSession implements PortForwardSession {
        private final LocalPortForward fwd;

        Fabric8PortForwardSession(LocalPortForward fwd) {
            this.fwd = fwd;
        }

        @Override
        public int localPort() {
            return fwd.getLocalPort();
        }

        @Override
        public void close() {
            try {
                fwd.close();
            } catch (Exception ignore) { //NOPMD EmptyCatchBlock - best-effort teardown
            }
        }
    }
}
