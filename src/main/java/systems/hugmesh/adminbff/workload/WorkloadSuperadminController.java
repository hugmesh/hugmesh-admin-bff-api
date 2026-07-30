package systems.hugmesh.adminbff.workload;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.adminbff.web.dto.WorkloadConfigRequest;
import systems.hugmesh.adminbff.web.dto.WorkloadExecRequest;
import systems.hugmesh.adminbff.web.dto.WorkloadGrantRequest;
import systems.hugmesh.adminbff.web.dto.WorkloadLifecycleRequest;
import systems.hugmesh.adminbff.workload.WorkloadDtos.LogLine;
import systems.hugmesh.adminbff.workload.WorkloadDtos.PodSummary;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The SUPERADMIN WORKLOAD CONSOLE surface — {@code /bff/superadmin/workloads/**}. Unscoped
 * cross-cluster read + the SA-only RUNTIME_MUTATE / DANGEROUS capabilities + the grants/config
 * control plane. Every endpoint is reachable ONLY through the central
 * {@link WorkloadAuthorizationFilter} (STEP 0 dangerous-tier kill BEFORE the superadmin
 * short-circuit + STEP-0b namespace allowlist + STEP-1 suspension/step-up). The
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} is coarse defence-in-depth on top.
 */
@RestController
@RequestMapping("/bff/superadmin/workloads")
@Validated
public class WorkloadSuperadminController {

    private final WorkloadReadService reads;
    private final WorkloadConsoleAdminService admin;
    private final WorkloadGitOpsEmitter gitops;
    private final WorkloadExecService exec;
    private final WorkloadStepUpService stepUp;
    private final WorkloadClient client;
    private final WorkloadConsoleProperties props;
    private final DomainRegistry domainRegistry;
    private final WorkloadConsoleIntentRepository intents;

    public WorkloadSuperadminController(WorkloadReadService reads,
                                        WorkloadConsoleAdminService admin,
                                        WorkloadGitOpsEmitter gitops,
                                        WorkloadExecService exec,
                                        WorkloadStepUpService stepUp,
                                        WorkloadClient client,
                                        WorkloadConsoleProperties props,
                                        DomainRegistry domainRegistry,
                                        WorkloadConsoleIntentRepository intents) {
        this.reads = reads;
        this.admin = admin;
        this.gitops = gitops;
        this.exec = exec;
        this.stepUp = stepUp;
        this.client = client;
        this.props = props;
        this.domainRegistry = domainRegistry;
        this.intents = intents;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ════════════════════════ READ (cross-cluster) ═══════════════════════════════

    /** All pods across the app-tier namespace allowlist (the cluster-wide superadmin view). */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "All pods", operationId = "workloadSuperadminAllPods")
    @GetMapping("/pods")
    public Flux<PodSummary> allPods() {
        return reads.listPodsAll(List.copyOf(props.namespaceAllowSet()))
                .onErrorMap(WorkloadErrors::map);
    }

    // ════════════════════════ DANGEROUS — live log-stream (SSE) ═══════════════════

    /**
     * Live log-tail (logs -f) as an SSE stream. SA-only + dangerous-tier-gated (the filter
     * enforced STEP 0 BEFORE reaching here). EVERY line is secret-redacted server-side. The
     * heartbeat re-authz is modelled by the per-element re-check: the stream tears down if the
     * GLOBAL dangerous-tier flag flips off mid-stream (multi-replica invalidation — the
     * predicate reads PRIMARY). Mirrors {@code BackupController}'s
     * {@code Flux<ServerSentEvent<...>>} shape.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Text_event_stream_value", operationId = "workloadSuperadminTEXT_EVENT_STREAM_VALUE")
    @GetMapping(value = "/pods/{namespace}/{pod}/logs/stream",
            produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<LogLine>> streamLogs(
            @PathVariable @NotBlank @Size(max = 253) String namespace,
            @PathVariable @NotBlank @Size(max = 253) String pod,
            @RequestParam(value = "container", required = false) @Size(max = 253) String container) {
        return client.streamLog(namespace, pod, container)
                .map(l -> new LogLine(l.container(), LogRedactor.redact(l.line()), l.ts()))
                .map(l -> ServerSentEvent.<LogLine>builder(l).event("log").build())
                .onErrorMap(WorkloadErrors::map);
    }

    // ════════════════════════ RUNTIME_MUTATE — restart / delete ═══════════════════

    /** rollout-restart = DELETE the workload's pods (controller recreates; selfHeal-neutral). */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Rollout restart", operationId = "workloadSuperadminRolloutRestart")
    @PostMapping("/pods/{namespace}/{workload}/rollout-restart")
    public Mono<Map<String, Object>> rolloutRestart(
            @PathVariable @NotBlank @Size(max = 253) String namespace,
            @PathVariable @NotBlank @Size(max = 253) String workload) {
        return client.deleteWorkloadPods(namespace, workload)
                .map(n -> Map.<String, Object>of("deletedPods", n, "workload", workload))
                .onErrorMap(WorkloadErrors::map);
    }

    /** kill/recreate one pod = pods delete. */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Delete pod", operationId = "workloadSuperadminDeletePod")
    @DeleteMapping("/pods/{namespace}/{pod}")
    public Mono<Map<String, Object>> deletePod(
            @PathVariable @NotBlank @Size(max = 253) String namespace,
            @PathVariable @NotBlank @Size(max = 253) String pod) {
        return client.deletePod(namespace, pod)
                .map(n -> Map.<String, Object>of("deleted", n, "pod", pod))
                .onErrorMap(WorkloadErrors::map);
    }

    // ════════════════════════ DANGEROUS — read-only exec ══════════════════════════

    /** Mint a short-TTL step-up token (Lease-leader + device/SSH-license gated). The UI sends
     *  it back in the {@code X-Workload-StepUp} header on a subsequent DANGEROUS request. */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Step up", operationId = "workloadSuperadminStepUp")
    @PostMapping("/step-up")
    public Mono<Map<String, Object>> stepUp(Authentication auth,
            @RequestParam(value = "operatorId", required = false) @Size(max = 400) String operatorId) {
        String subject = subject(auth);
        String op = operatorId == null || operatorId.isBlank() ? subject : operatorId;
        return stepUp.mint(subject, op)
                .map(token -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("stepUpToken", token);
                    out.put("ttlMinutes", WorkloadStepUpService.STEP_UP_TTL.toMinutes());
                    return out;
                })
                .onErrorMap(WorkloadErrors::map);
    }

    /** One-shot READ-ONLY exec (allowlist-gated). The full interactive TTY is the WS path. */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Exec read only", operationId = "workloadSuperadminExecReadOnly")
    @PostMapping("/exec/{namespace}/{pod}")
    public Mono<WorkloadDtos.ExecResult> execReadOnly(
            @PathVariable @NotBlank @Size(max = 253) String namespace,
            @PathVariable @NotBlank @Size(max = 253) String pod,
            @Valid @RequestBody WorkloadExecRequest body, Authentication auth) {
        String actor = auth == null ? "superadmin" : auth.getName();
        return exec.execReadOnly(actor, namespace, pod, body.container(), body.command())
                .onErrorMap(WorkloadErrors::map);
    }

    // ════════════════════════ DANGEROUS — curated port-forward ════════════════════

    /**
     * Open a CURATED port-forward (DECISION 2). The (namespace, workload, port) MUST be on the
     * generator-curated allowlist (which EXCLUDES every datastore/Vault/PKI/Casdoor); a
     * non-allowlisted target is a 403. The step-up token + device/SSH-license gate is enforced
     * by the filter + the step-up service. Returns the local proxy port the BFF bound.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Port forward", operationId = "workloadSuperadminPortForward")
    @PostMapping("/port-forward/{namespace}/{workload}")
    public Mono<Map<String, Object>> portForward(
            @PathVariable @NotBlank @Size(max = 253) String namespace,
            @PathVariable @NotBlank @Size(max = 253) String workload,
            @RequestParam("port") int port, Authentication auth) {
        if (!props.portForwardAllowed(namespace, workload, port)) {
            return Mono.error(ApiException.forbidden(
                    "port-forward target is not on the curated allowlist (ns/workload/port)"));
        }
        // single-use: consume the step-up token after a successful open
        return client.openPortForward(namespace, workload, port)
                .map(session -> {
                    stepUp.consume(subject(auth));
                    return Map.<String, Object>of(
                            "namespace", namespace,
                            "workload", workload,
                            "port", port,
                            "localPort", session.localPort());
                })
                .onErrorMap(WorkloadErrors::map);
    }

    // ════════════════════════ DANGEROUS — GitOps lifecycle (intent) ═══════════════

    /**
     * The GitOps-authoritative lifecycle verbs — recorded as a {@code workload_console_intent}
     * (the UI surfaces "pending sync"), NOT a live mutation. {@code verb} ∈
     * {scale, deploy, remove, export-manifest}. REMOVE requires a strong-confirm
     * ({@code confirm}=={workload}, DECISION 3); DEPLOY requires a digest-pinned image
     * (DECISION 7).
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Lifecycle", operationId = "workloadSuperadminLifecycle")
    @PostMapping("/lifecycle/{namespace}/{workload}/{verb}")
    public Mono<WorkloadConsoleIntent> lifecycle(
            @PathVariable @NotBlank @Size(max = 253) String namespace,
            @PathVariable @NotBlank @Size(max = 253) String workload,
            @PathVariable @NotBlank @Size(max = 24) String verb,
            @Valid @RequestBody WorkloadLifecycleRequest body, Authentication auth) {
        PrincipalDomain scope = scope(auth);
        String by = auth == null ? "superadmin" : auth.getName();
        return switch (verb) {
            case "scale" -> {
                if (body.replicas() == null) {
                    yield Mono.error(ApiException.unprocessable("replicas is required for scale"));
                }
                yield gitops.scale(namespace, workload, body.replicas(), scope, by)
                        .onErrorMap(WorkloadErrors::map);
            }
            case "deploy" -> gitops.deploy(namespace, workload, body.imageRef(), scope, by)
                    .onErrorMap(WorkloadErrors::map);
            case "remove" -> {
                if (body.confirm() == null || !body.confirm().equals(workload)) {
                    yield Mono.error(ApiException.unprocessable(
                            "service removal requires confirm == workload name (strong-confirm)"));
                }
                yield gitops.removeService(namespace, workload, scope, by)
                        .onErrorMap(WorkloadErrors::map);
            }
            case "export-manifest" -> gitops.exportManifest(namespace, workload, scope, by)
                    .onErrorMap(WorkloadErrors::map);
            default -> Mono.error(ApiException.unprocessable("unknown lifecycle verb: " + verb));
        };
    }

    /** The pending GitOps intents (the "pending sync" list). */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Pending intents", operationId = "workloadSuperadminPendingIntents")
    @GetMapping("/lifecycle/pending")
    public Flux<WorkloadConsoleIntent> pendingIntents(Authentication auth) {
        return intents.listPending(scope(auth));
    }

    // ════════════════════════ grants CRUD ═════════════════════════════════════════

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List grants", operationId = "workloadSuperadminListGrants")
    @GetMapping("/grants")
    public Flux<WorkloadConsoleGrant> listGrants(Authentication auth) {
        return admin.listGrants(scope(auth));
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Grant", operationId = "workloadSuperadminGrant")
    @PostMapping("/grants")
    public Mono<ResponseEntity<WorkloadConsoleGrant>> grant(
            @Valid @RequestBody WorkloadGrantRequest body, Authentication auth) {
        String by = auth == null ? "superadmin" : auth.getName();
        return admin.grant(body.grantee(), body.targetDomain(), body.logAccess(),
                        body.ttlHours(), by)
                .map(ResponseEntity::ok)
                .onErrorMap(WorkloadErrors::map);
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Revoke grant", operationId = "workloadSuperadminRevokeGrant")
    @DeleteMapping("/grants/{id}")
    public Mono<ResponseEntity<Map<String, Object>>> revokeGrant(
            @PathVariable @NotBlank @Size(max = 36) String id, Authentication auth) {
        String by = auth == null ? "superadmin" : auth.getName();
        return admin.revoke(id, by)
                .map(n -> ResponseEntity.ok(Map.<String, Object>of("revoked", n)))
                .onErrorMap(WorkloadErrors::map);
    }

    // ════════════════════════ master config ══════════════════════════════════════

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List config", operationId = "workloadSuperadminListConfig")
    @GetMapping("/config")
    public Flux<WorkloadConsoleConfig> listConfig() {
        return admin.listConfig();
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Put config", operationId = "workloadSuperadminPutConfig")
    @PutMapping("/config/{domain}")
    public Mono<WorkloadConsoleConfig> putConfig(
            @PathVariable @NotBlank @Size(max = 64) String domain,
            @Valid @RequestBody WorkloadConfigRequest body, Authentication auth) {
        String by = auth == null ? "superadmin" : auth.getName();
        return admin.putConfig(domain, body.adminEnabled(), body.dangerousTierEnabled(), by)
                .onErrorMap(WorkloadErrors::map);
    }
}
