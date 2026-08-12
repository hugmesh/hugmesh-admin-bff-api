package net.hugmesh.adminbff.workload;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.workload.WorkloadDtos.NetworkSummary;
import net.hugmesh.adminbff.workload.WorkloadDtos.PodInspect;
import net.hugmesh.adminbff.workload.WorkloadDtos.PodMetrics;
import net.hugmesh.adminbff.workload.WorkloadDtos.PodSummary;
import net.hugmesh.adminbff.workload.WorkloadDtos.VolumeSummary;
import net.hugmesh.adminbff.workload.WorkloadDtos.WorkloadEvent;

import java.util.List;

/**
 * The READ surface logic shared by the admin (own-domain, grant-gated) and superadmin
 * (cross-cluster) controllers. The central {@link WorkloadAuthorizationFilter} has already
 * authorized the request (tier + grant + master flags + STEP-0b namespace allowlist); this
 * service applies the STEP-7 owner-chain attribution for the ADMIN surface — an admin may
 * only see workloads whose owner-chain domain == their scope domain.
 *
 * <p>Attribution is the {@code hugmesh.systems/domain} (or the per-brand) label the
 * generator stamps via ArgoCD's owner chain (NEVER a forgeable pod-applied label — but on a
 * separate-brand-cluster topology the namespace allowlist + the single-brand BFF SA is the
 * authoritative wall, and this label filter is the in-cluster defence-in-depth). On the
 * single-brand-cluster default every app-tier workload is the brand's own, so the filter is a
 * no-op safety net; it becomes load-bearing only in the OPEN future shared-cluster mode.
 */
@Service
public class WorkloadReadService {

    /** The owner-chain attribution label (the generator stamps this via the ArgoCD
     *  Application owner chain, not a pod-applied label). */
    public static final String DOMAIN_LABEL = "hugmesh.systems/domain";

    private final WorkloadClient client;

    public WorkloadReadService(WorkloadClient client) {
        this.client = client;
    }

    // ── pods ───────────────────────────────────────────────────────────────────

    /** List pods in one namespace, attributed to the scope (admin: own-domain only). */
    public Flux<PodSummary> listPods(String namespace, PrincipalDomain scope) {
        return client.listPods(namespace).filter(p -> attributed(p.workload(), null, scope));
    }

    /** List pods across the whole app-tier allowlist (superadmin cross-cluster read). */
    public Flux<PodSummary> listPodsAll(List<String> namespaces) {
        return client.listPodsAll(namespaces);
    }

    public Mono<PodInspect> inspectPod(String namespace, String name, PrincipalDomain scope) {
        return client.inspectPod(namespace, name)
                .filter(p -> attributed(p.workload(), p.labels() == null
                        ? null : p.labels().get(DOMAIN_LABEL), scope));
    }

    // ── namespace-scoped reads (own-domain, STEP-7 owner-chain attributed) ────────
    // metrics/events/volumes/network/logs target a whole namespace, so the STEP-7 cut is the
    // NAMESPACE's owner-chain domain (resolved once) rather than a per-row label. A scoped admin
    // whose domain != the namespace's owner-chain domain is denied at source — the cross-tenant
    // read finding [4]. A superadmin (or an unlabelled single-brand-cluster namespace) sees all,
    // identical to attributed(...).

    public Flux<PodMetrics> metrics(String namespace, PrincipalDomain scope) {
        return attributedNamespace(namespace, scope).flatMapMany(ok -> client.podMetrics(namespace));
    }

    public Flux<WorkloadEvent> events(String namespace, PrincipalDomain scope) {
        return attributedNamespace(namespace, scope).flatMapMany(ok -> client.events(namespace));
    }

    public Flux<VolumeSummary> volumes(String namespace, PrincipalDomain scope) {
        return attributedNamespace(namespace, scope).flatMapMany(ok -> client.volumes(namespace));
    }

    public Flux<NetworkSummary> network(String namespace, PrincipalDomain scope) {
        return attributedNamespace(namespace, scope).flatMapMany(ok -> client.network(namespace));
    }

    /** A bounded, redacted, NON-stream log read (the admin log_access path + the superadmin
     *  history fallback). EVERY line is redacted server-side. The pod's own-domain owner-chain
     *  label gates the read (STEP-7) BEFORE any log bytes are fetched — logs are the most
     *  sensitive surface, so cross-domain readers see a 404 (empty), never another brand's lines. */
    public Mono<String> readLog(String namespace, String pod, String container, int tailLines,
                                PrincipalDomain scope) {
        return client.inspectPod(namespace, pod)
                .filter(p -> attributed(p.workload(), p.labels() == null
                        ? null : p.labels().get(DOMAIN_LABEL), scope))
                .flatMap(p -> client.readLog(namespace, pod, container, tailLines))
                .map(WorkloadReadService::redactMultiline);
    }

    /**
     * STEP-7 namespace-level guard for the namespace-wide reads: a SUPERADMIN (unscoped) always
     * passes (no k8s lookup); a scoped admin passes only when the namespace's owner-chain domain
     * label matches their scope domain — OR the label is absent (single-brand-cluster default).
     * Resolved through the SAME owner-chain {@link #DOMAIN_LABEL} the inspect path trusts, never a
     * forgeable pod-applied label. EMITS {@code true} when the read is allowed and is EMPTY when
     * the namespace's domain != the scope domain (deny) — so the read methods'
     * {@code flatMapMany} produces another brand's telemetry ONLY on a pass, never on a deny.
     */
    private Mono<Boolean> attributedNamespace(String namespace, PrincipalDomain scope) {
        if (scope == null || scope.superadmin()) return Mono.just(Boolean.TRUE);
        // namespaceDomain emits the owner-chain label, or "" when the namespace carries none
        // (defaultIfEmpty keeps the unlabelled single-brand-cluster case from collapsing the
        // stream before the attributed() check runs). Pass => emit true; mismatch => empty (deny).
        return client.namespaceDomain(namespace)
                .defaultIfEmpty("")
                .filter(domainLabel -> attributed(namespace, domainLabel, scope))
                .map(domainLabel -> Boolean.TRUE);
    }

    static String redactMultiline(String log) {
        if (log == null) return null;
        String[] lines = log.split("\n", -1);
        StringBuilder sb = new StringBuilder(log.length());
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) sb.append('\n');
            sb.append(LogRedactor.redact(lines[i]));
        }
        return sb.toString();
    }

    /**
     * STEP-7 owner-chain attribution: a SUPERADMIN (unscoped) sees everything; a scoped
     * admin sees a workload only when its owner-chain domain label matches their scope domain
     * — OR the label is absent (the single-brand-cluster default: the namespace allowlist +
     * the single-brand BFF SA is the authoritative wall, so an unlabelled app-tier workload is
     * by definition this brand's own).
     */
    @SuppressWarnings("PMD.UnusedFormalParameter")
    private static boolean attributed(String workload, String domainLabel, PrincipalDomain scope) {
        if (scope == null || scope.superadmin()) return true;
        if (domainLabel == null || domainLabel.isBlank()) return true;
        return domainLabel.equals(scope.domain());
    }
}
