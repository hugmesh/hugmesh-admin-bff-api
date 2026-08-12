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
 * The DEFAULT, FAIL-CLOSED {@link WorkloadClient}. With no real k8s client wired (the
 * cluster-less dev/test/CI default, OR any deployment that has not flipped
 * {@code app.workload-console.k8s.enabled=true}), every read raises a
 * {@link WorkloadClientException#unavailable} (the controller maps it to an explicit 503 —
 * NEVER an empty 200 that a caller could mistake for "no workloads"), and every
 * mutate/stream/exec/port-forward raises unavailable too. There is NO code path here that
 * returns success: the seam can only ever fail-closed.
 *
 * <p>This is the bean Spring picks unless the conditional {@code Fabric8WorkloadClient} is
 * activated, so the whole feature is inert until deliberately enabled in-cluster.
 */
public class NoopWorkloadClient implements WorkloadClient {

    private static final String MSG =
            "workload console k8s client is not available "
            + "(app.workload-console.k8s.enabled is false or no cluster) — fail-closed";

    @Override
    public boolean available() {
        return false;
    }

    private <T> Flux<T> deadFlux() {
        return Flux.error(WorkloadClientException.unavailable(MSG));
    }

    private <T> Mono<T> deadMono() {
        return Mono.error(WorkloadClientException.unavailable(MSG));
    }

    @Override
    public Flux<PodSummary> listPods(String namespace) {
        return deadFlux();
    }

    @Override
    public Flux<PodSummary> listPodsAll(List<String> namespaces) {
        return deadFlux();
    }

    @Override
    public Mono<PodInspect> inspectPod(String namespace, String name) {
        return deadMono();
    }

    @Override
    public Mono<String> namespaceDomain(String namespace) {
        // Fail-closed: with no cluster we cannot attribute the namespace; the data reads also
        // fail-closed (503), so the attributed guard surfaces unavailable rather than ALLOW.
        return deadMono();
    }

    @Override
    public Flux<PodMetrics> podMetrics(String namespace) {
        return deadFlux();
    }

    @Override
    public Flux<WorkloadEvent> events(String namespace) {
        return deadFlux();
    }

    @Override
    public Flux<VolumeSummary> volumes(String namespace) {
        return deadFlux();
    }

    @Override
    public Flux<NetworkSummary> network(String namespace) {
        return deadFlux();
    }

    @Override
    public Mono<String> readLog(String namespace, String pod, String container, int tailLines) {
        return deadMono();
    }

    @Override
    public Flux<LogLine> streamLog(String namespace, String pod, String container) {
        return deadFlux();
    }

    @Override
    public Mono<Integer> deletePod(String namespace, String pod) {
        return deadMono();
    }

    @Override
    public Mono<Integer> deleteWorkloadPods(String namespace, String workload) {
        return deadMono();
    }

    @Override
    public Mono<ExecResult> execReadOnly(String namespace, String pod, String container,
                                         List<String> command) {
        return deadMono();
    }

    @Override
    public Mono<ExecSession> openExec(String namespace, String pod, String container,
                                      List<String> command) {
        return deadMono();
    }

    @Override
    public Mono<Void> rescheduleAfterExec(String namespace, String pod) {
        return deadMono();
    }

    @Override
    public Mono<PortForwardSession> openPortForward(String namespace, String workload, int port) {
        return deadMono();
    }
}
