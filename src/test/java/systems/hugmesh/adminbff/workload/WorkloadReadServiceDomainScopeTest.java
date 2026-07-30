package systems.hugmesh.adminbff.workload;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.workload.WorkloadDtos.NetworkSummary;
import systems.hugmesh.adminbff.workload.WorkloadDtos.PodInspect;
import systems.hugmesh.adminbff.workload.WorkloadDtos.PodMetrics;
import systems.hugmesh.adminbff.workload.WorkloadDtos.VolumeSummary;
import systems.hugmesh.adminbff.workload.WorkloadDtos.WorkloadEvent;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * STEP-7 owner-chain attribution for the NAMESPACE-WIDE workload reads
 * (metrics/events/volumes/network/logs) — the regression bar for finding [4]
 * (WorkloadAdminController cross-tenant read: these reads skipped the per-domain owner-chain
 * filter that pods/inspect already apply).
 *
 * <p>A scoped brand-X admin targeting a brand-Y namespace MUST get an EMPTY result (the read is
 * cut at source, no brand-Y telemetry/logs leak); a scoped admin targeting their OWN namespace —
 * and a SUPERADMIN targeting any namespace — still sees the data. The namespace's owner-chain
 * domain is resolved through {@link WorkloadClient#namespaceDomain} (the
 * {@code hugmesh.systems/domain} label), never a forgeable pod-applied label.
 */
class WorkloadReadServiceDomainScopeTest {

    private WorkloadClient client;
    private WorkloadReadService reads;

    private static final PrincipalDomain BRANDX = WorkloadScopeFixtures.adminScope("brandx");
    private static final PrincipalDomain SUPERADMIN = WorkloadScopeFixtures.superadminScope();

    @BeforeEach
    void setup() {
        client = mock(WorkloadClient.class);
        reads = new WorkloadReadService(client);
        // The underlying telemetry reads always have data; the guard is what gates access.
        when(client.podMetrics(anyString()))
                .thenReturn(Flux.just(new PodMetrics("ns", "pod", "1m", "1Mi")));
        when(client.events(anyString()))
                .thenReturn(Flux.just(new WorkloadEvent("ns", "Normal", "Started", "Pod/pod",
                        "ok", Instant.now(), 1)));
        when(client.volumes(anyString()))
                .thenReturn(Flux.just(new VolumeSummary("ns", "pvc", "Bound", "1Gi", "std",
                        List.of("ReadWriteOnce"))));
        when(client.network(anyString()))
                .thenReturn(Flux.just(new NetworkSummary("ns", "Service", "svc", "ClusterIP")));
    }

    private static PodInspect pod(String domainLabel) {
        Map<String, String> labels = domainLabel == null ? Map.of()
                : Map.of(WorkloadReadService.DOMAIN_LABEL, domainLabel);
        return new PodInspect("ns", "pod", "deploy", "Running", "node", "sa",
                Instant.now(), List.of(), labels, "ReplicaSet", "deploy-rs");
    }

    // ── cross-domain DENY (the exploit): brand-X admin → brand-Y namespace ────────

    @Test
    void scopedAdmin_crossDomainNamespace_metricsEmpty() {
        when(client.namespaceDomain("brandy-ns")).thenReturn(Mono.just("brandy"));

        StepVerifier.create(reads.metrics("brandy-ns", BRANDX)).verifyComplete();
        // the guard cut the read BEFORE any brand-Y telemetry was fetched
        verify(client, never()).podMetrics(anyString());
    }

    @Test
    void scopedAdmin_crossDomainNamespace_eventsEmpty() {
        when(client.namespaceDomain("brandy-ns")).thenReturn(Mono.just("brandy"));

        StepVerifier.create(reads.events("brandy-ns", BRANDX)).verifyComplete();
        verify(client, never()).events(anyString());
    }

    @Test
    void scopedAdmin_crossDomainNamespace_volumesEmpty() {
        when(client.namespaceDomain("brandy-ns")).thenReturn(Mono.just("brandy"));

        StepVerifier.create(reads.volumes("brandy-ns", BRANDX)).verifyComplete();
        verify(client, never()).volumes(anyString());
    }

    @Test
    void scopedAdmin_crossDomainNamespace_networkEmpty() {
        when(client.namespaceDomain("brandy-ns")).thenReturn(Mono.just("brandy"));

        StepVerifier.create(reads.network("brandy-ns", BRANDX)).verifyComplete();
        verify(client, never()).network(anyString());
    }

    @Test
    void scopedAdmin_crossDomainPod_logsEmpty_andBytesNeverRead() {
        // The pod's own owner-chain label is brand-Y; the brand-X admin must not read its lines.
        when(client.inspectPod("brandy-ns", "pod")).thenReturn(Mono.just(pod("brandy")));

        StepVerifier.create(reads.readLog("brandy-ns", "pod", "c", 100, BRANDX)).verifyComplete();
        verify(client, never()).readLog(anyString(), anyString(), any(), anyInt());
    }

    // ── legit ALLOW: own-domain admin sees own-domain data ────────────────────────

    @Test
    void scopedAdmin_ownDomainNamespace_metricsReturned() {
        when(client.namespaceDomain("brandx-ns")).thenReturn(Mono.just("brandx"));

        StepVerifier.create(reads.metrics("brandx-ns", BRANDX)).expectNextCount(1).verifyComplete();
    }

    @Test
    void scopedAdmin_ownDomainPod_logsReturned() {
        when(client.inspectPod("brandx-ns", "pod")).thenReturn(Mono.just(pod("brandx")));
        when(client.readLog("brandx-ns", "pod", "c", 100)).thenReturn(Mono.just("hello"));

        StepVerifier.create(reads.readLog("brandx-ns", "pod", "c", 100, BRANDX))
                .expectNext("hello").verifyComplete();
    }

    // ── unlabelled namespace == single-brand-cluster default: own brand, ALLOW ─────

    @Test
    void scopedAdmin_unlabelledNamespace_metricsReturned() {
        // no owner-chain label resolvable → namespaceDomain emits empty → treated as own brand.
        when(client.namespaceDomain("plain-ns")).thenReturn(Mono.empty());

        StepVerifier.create(reads.metrics("plain-ns", BRANDX)).expectNextCount(1).verifyComplete();
    }

    @Test
    void scopedAdmin_unlabelledPod_logsReturned() {
        when(client.inspectPod("plain-ns", "pod")).thenReturn(Mono.just(pod(null)));
        when(client.readLog("plain-ns", "pod", "c", 100)).thenReturn(Mono.just("hi"));

        StepVerifier.create(reads.readLog("plain-ns", "pod", "c", 100, BRANDX))
                .expectNext("hi").verifyComplete();
    }

    // ── superadmin is unscoped: sees any namespace, NO attribution lookup ──────────

    @Test
    void superadmin_crossDomainNamespace_metricsReturned_withoutNamespaceLookup() {
        StepVerifier.create(reads.metrics("brandy-ns", SUPERADMIN)).expectNextCount(1).verifyComplete();
        // a superadmin short-circuits the guard — no owner-chain resolution call is made
        verify(client, never()).namespaceDomain(anyString());
    }

    @Test
    void superadmin_crossDomainPod_logsReturned() {
        when(client.inspectPod("brandy-ns", "pod")).thenReturn(Mono.just(pod("brandy")));
        when(client.readLog("brandy-ns", "pod", "c", 100)).thenReturn(Mono.just("root-log"));

        StepVerifier.create(reads.readLog("brandy-ns", "pod", "c", 100, SUPERADMIN))
                .expectNext("root-log").verifyComplete();
    }
}
