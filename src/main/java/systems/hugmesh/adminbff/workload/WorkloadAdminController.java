package systems.hugmesh.adminbff.workload;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.workload.WorkloadDtos.NetworkSummary;
import systems.hugmesh.adminbff.workload.WorkloadDtos.PodInspect;
import systems.hugmesh.adminbff.workload.WorkloadDtos.PodMetrics;
import systems.hugmesh.adminbff.workload.WorkloadDtos.PodSummary;
import systems.hugmesh.adminbff.workload.WorkloadDtos.VolumeSummary;
import systems.hugmesh.adminbff.workload.WorkloadDtos.WorkloadEvent;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The ADMIN WORKLOAD CONSOLE READ surface — {@code /bff/admin/workloads/**}. READ-ONLY,
 * own-domain, app-tier, grant-gated. <b>ZERO mutating mappings</b> (the architecture test
 * {@code WorkloadAdminControllerArchTest} enforces this — no POST/PUT/DELETE/PATCH, no
 * exec/stream/lifecycle mapping ever appears here): a granted admin can read status /
 * topology / metrics but NEVER stream/exec/mutate (DECISION 4).
 *
 * <p>Every method is reachable ONLY through the central {@link WorkloadAuthorizationFilter}
 * (STEP 0..6 + STEP-0b namespace allowlist); a DENY 404s BEFORE this controller is hit, so
 * the feature's existence is never leaked. The {@code @PreAuthorize} here is coarse
 * defence-in-depth (SUPERADMIN also reaches the admin surface via the role hierarchy, but
 * the predicate is the real gate). The {@link #capability} probe returns 404-on-deny (handled
 * entirely by the filter when access is absent) — a 200 here means "you have a live grant".
 */
@RestController
@RequestMapping("/bff/admin/workloads")
@Validated
public class WorkloadAdminController {

    private final WorkloadReadService reads;
    private final DomainRegistry domainRegistry;

    public WorkloadAdminController(WorkloadReadService reads, DomainRegistry domainRegistry) {
        this.reads = reads;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    // ── capability probe (404-on-deny via the filter; 200 = live grant) ──────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Capability", operationId = "workloadAdminCapability")
    @GetMapping("/capability")
    public Mono<Map<String, Object>> capability(Authentication auth) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", true);
        out.put("readOnly", true);
        out.put("domain", scope(auth).domain());
        return Mono.just(out);
    }

    // ── pods (own-domain app-tier, attributed) ───────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Pods", operationId = "workloadAdminPods")
    @GetMapping("/pods/{namespace}")
    public Flux<PodSummary> pods(
            @PathVariable @NotBlank @Size(max = 253) String namespace, Authentication auth) {
        return reads.listPods(namespace, scope(auth))
                .onErrorMap(WorkloadErrors::map);
    }

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Inspect", operationId = "workloadAdminInspect")
    @GetMapping("/pods/{namespace}/{name}")
    public Mono<PodInspect> inspect(
            @PathVariable @NotBlank @Size(max = 253) String namespace,
            @PathVariable @NotBlank @Size(max = 253) String name, Authentication auth) {
        return reads.inspectPod(namespace, name, scope(auth))
                .switchIfEmpty(Mono.error(
                        systems.hugmesh.commons.web.ApiException.notFound("pod not found")))
                .onErrorMap(WorkloadErrors::map);
    }

    // ── non-stream redacted logs (log_access-gated by the filter) ────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Logs", operationId = "workloadAdminLogs")
    @GetMapping("/pods/{namespace}/{name}/logs")
    public Mono<Map<String, Object>> logs(
            @PathVariable @NotBlank @Size(max = 253) String namespace,
            @PathVariable @NotBlank @Size(max = 253) String name,
            @RequestParam(value = "container", required = false) @Size(max = 253) String container,
            @RequestParam(value = "tail", defaultValue = "200") int tail, Authentication auth) {
        return reads.readLog(namespace, name, container, Math.min(Math.max(tail, 1), 2000), scope(auth))
                .map(body -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("pod", name);
                    out.put("container", container);
                    out.put("redacted", true);
                    out.put("log", body);
                    return out;
                })
                // empty == pod not found OR owner-chain domain != scope (STEP-7 cross-domain
                // deny): 404, never an empty 200 a cross-tenant caller could probe.
                .switchIfEmpty(Mono.error(
                        systems.hugmesh.commons.web.ApiException.notFound("pod not found")))
                .onErrorMap(WorkloadErrors::map);
    }

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Metrics", operationId = "workloadAdminMetrics")
    @GetMapping("/metrics/{namespace}")
    public Flux<PodMetrics> metrics(
            @PathVariable @NotBlank @Size(max = 253) String namespace, Authentication auth) {
        return reads.metrics(namespace, scope(auth)).onErrorMap(WorkloadErrors::map);
    }

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Events", operationId = "workloadAdminEvents")
    @GetMapping("/events/{namespace}")
    public Flux<WorkloadEvent> events(
            @PathVariable @NotBlank @Size(max = 253) String namespace, Authentication auth) {
        return reads.events(namespace, scope(auth)).onErrorMap(WorkloadErrors::map);
    }

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Storage", operationId = "workloadAdminStorage")
    @GetMapping("/storage/{namespace}")
    public Flux<VolumeSummary> storage(
            @PathVariable @NotBlank @Size(max = 253) String namespace, Authentication auth) {
        return reads.volumes(namespace, scope(auth)).onErrorMap(WorkloadErrors::map);
    }

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Network", operationId = "workloadAdminNetwork")
    @GetMapping("/network/{namespace}")
    public Flux<NetworkSummary> network(
            @PathVariable @NotBlank @Size(max = 253) String namespace, Authentication auth) {
        return reads.network(namespace, scope(auth)).onErrorMap(WorkloadErrors::map);
    }
}
