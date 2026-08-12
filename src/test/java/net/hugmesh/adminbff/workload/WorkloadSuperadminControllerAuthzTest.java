package net.hugmesh.adminbff.workload;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.adminbff.workload.WorkloadDtos.PodSummary;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * HTTP authorization matrix for the MOST DANGEROUS surface in the BFF — the
 * {@link WorkloadSuperadminController} ({@code /bff/superadmin/workloads/**}: cross-cluster
 * read + the SUPERADMIN-only DANGEROUS exec / SSE log-stream / step-up / port-forward /
 * GitOps-lifecycle / grants / config). Driven through the REAL {@link SecurityConfig} (the
 * production {@code /bff/superadmin/** -> hasRole('SUPERADMIN')} path gate + the role
 * hierarchy + the per-method {@code @PreAuthorize("hasRole('SUPERADMIN')")}) with
 * {@code mockJwt} principals, exactly like the existing {@code MethodSecuritySuperadminBypassTest}
 * / {@code DesktopSshTerminalControllerTest} pattern.
 *
 * <p><b>Filter interplay.</b> The mandatory {@link WorkloadAuthorizationFilter} runs at
 * {@code LOWEST_PRECEDENCE} (AFTER Spring Security's authorization web filter). To isolate
 * the ROLE/TIER authz boundary under test, the filter is configured PERMISSIVE here
 * (feature enabled, every namespace allowed, {@code decide(...)} ALLOWs) UNLESS a test
 * deliberately tightens it (the step-up + cross-namespace-isolation tests). That way:
 * <ul>
 *   <li>the unauth-401 / wrong-role-403 assertions are decided by Spring Security BEFORE the
 *       filter (so they hold regardless of filter config) — and the controller's service
 *       collaborators are {@code verify(...).never()} to prove the guarded body never ran
 *       (MUTATION-RESISTANT: delete the {@code @PreAuthorize}/path-rule and an ADMIN reaches
 *       the body, flipping these red);</li>
 *   <li>the authorized-superadmin path actually reaches the controller (200), proving the
 *       gate ADMITS superadmin (not a blanket deny);</li>
 *   <li>the step-up + per-stream-isolation DENIES are decided by the filter's
 *       {@link WorkloadAuthorizationService}/namespace gate and asserted as 403 with the
 *       k8s/exec client {@code verify(...).never()} (MUTATION-RESISTANT: the deny is the
 *       real filter's, not an in-test re-derivation).</li>
 * </ul>
 */
@WebFluxTest(controllers = WorkloadSuperadminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class WorkloadSuperadminControllerAuthzTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    // Controller collaborators
    @MockitoBean WorkloadReadService reads;
    @MockitoBean WorkloadConsoleAdminService admin;
    @MockitoBean WorkloadGitOpsEmitter gitops;
    @MockitoBean WorkloadExecService exec;
    @MockitoBean WorkloadStepUpService stepUp;
    @MockitoBean WorkloadClient client;
    @MockitoBean WorkloadConsoleProperties props;
    @MockitoBean WorkloadConsoleIntentRepository intents;

    // Filter collaborators (the central WorkloadAuthorizationFilter resolves these via
    // ObjectProvider). Configured PERMISSIVE so the ROLE/TIER gate is the decider, EXCEPT
    // where a test tightens decide(...)/namespaceAllowed(...).
    @MockitoBean WorkloadAuthorizationService authz;
    @MockitoBean UsageService usage;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private void filterAllowsEverything() {
        lenient().when(props.isEnabled()).thenReturn(true);
        lenient().when(props.namespaceAllowed(anyString())).thenReturn(true);
        lenient().when(props.namespaceAllowSet()).thenReturn(java.util.Set.of("app"));
        lenient().when(authz.decide(any(), any(), anyBoolean(), anyBoolean(), any()))
                .thenReturn(Mono.just(WorkloadAccessDecision.allow(true, true)));
        lenient().when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
    }

    private WebTestClient as(String... roles) {
        SimpleGrantedAuthority[] auths = new SimpleGrantedAuthority[roles.length];
        for (int i = 0; i < roles.length; i++) auths[i] = new SimpleGrantedAuthority(roles[i]);
        return web.mutateWith(mockJwt().jwt(j -> j.subject("subj")).authorities(auths));
    }

    private WebTestClient asSuperadmin() { return as("ROLE_USER", "ROLE_SUPERADMIN"); }
    private WebTestClient asAdmin()      { return as("ROLE_USER", "ROLE_ADMIN"); }
    private WebTestClient asMod()        { return as("ROLE_USER", "ROLE_MOD"); }
    private WebTestClient asUser()       { return as("ROLE_USER"); }

    // ════════════════════════ authorized SUPERADMIN reaches the surface ═══════════════

    @Test
    void pods_asSuperadmin_authorized_reachesReadService() {
        filterAllowsEverything();
        when(reads.listPodsAll(any())).thenReturn(Flux.empty());
        asSuperadmin().get().uri("/bff/superadmin/workloads/pods")
                .exchange().expectStatus().isOk();
        verify(reads).listPodsAll(any());
    }

    @Test
    void execReadOnly_asSuperadmin_authorized_reachesExecService() {
        filterAllowsEverything();
        when(exec.execReadOnly(anyString(), eq("app"), eq("pod-1"), any(), any()))
                .thenReturn(Mono.just(new WorkloadDtos.ExecResult(0, "ok", "")));
        asSuperadmin().post().uri("/bff/superadmin/workloads/exec/app/pod-1")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"command\":[\"cat\",\"/etc/hostname\"]}")
                .exchange().expectStatus().isOk();
        verify(exec).execReadOnly(anyString(), eq("app"), eq("pod-1"), any(), any());
    }

    @Test
    void stepUp_asSuperadmin_authorized_mintsToken() {
        filterAllowsEverything();
        when(stepUp.mint(anyString(), anyString())).thenReturn(Mono.just("tok-123"));
        asSuperadmin().post().uri("/bff/superadmin/workloads/step-up")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.stepUpToken").isEqualTo("tok-123");
        verify(stepUp).mint(anyString(), anyString());
    }

    @Test
    void rolloutRestart_asSuperadmin_authorized_reachesClient() {
        filterAllowsEverything();
        when(client.deleteWorkloadPods(eq("app"), eq("wl-1"))).thenReturn(Mono.just(2));
        asSuperadmin().post().uri("/bff/superadmin/workloads/pods/app/wl-1/rollout-restart")
                .exchange().expectStatus().isOk();
        verify(client).deleteWorkloadPods(eq("app"), eq("wl-1"));
    }

    @Test
    void listGrants_asSuperadmin_authorized() {
        filterAllowsEverything();
        when(admin.listGrants(any())).thenReturn(Flux.empty());
        asSuperadmin().get().uri("/bff/superadmin/workloads/grants")
                .exchange().expectStatus().isOk();
        verify(admin).listGrants(any());
    }

    @Test
    void listConfig_asSuperadmin_authorized() {
        filterAllowsEverything();
        when(admin.listConfig()).thenReturn(Flux.empty());
        asSuperadmin().get().uri("/bff/superadmin/workloads/config")
                .exchange().expectStatus().isOk();
        verify(admin).listConfig();
    }

    // ════════════════════════ CROSS-TIER: ADMIN cannot reach the superadmin surface ════

    @Test
    void pods_asAdmin_isForbidden_andNeverReads() {
        filterAllowsEverything();
        asAdmin().get().uri("/bff/superadmin/workloads/pods")
                .exchange().expectStatus().isForbidden();
        verify(reads, never()).listPodsAll(any());
    }

    @Test
    void execReadOnly_asAdmin_crossTier_isForbidden_andNeverExecs() {
        // The sharpest cross-TIER edge: an ADMIN (the highest non-superadmin role) must
        // NEVER reach the read-only exec capability. There is no ADMIN>SUPERADMIN edge.
        filterAllowsEverything();
        asAdmin().post().uri("/bff/superadmin/workloads/exec/app/pod-1")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"command\":[\"cat\",\"/etc/hostname\"]}")
                .exchange().expectStatus().isForbidden();
        verify(exec, never()).execReadOnly(anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    void streamLogs_asAdmin_crossTier_isForbidden_andNeverStreams() {
        filterAllowsEverything();
        asAdmin().get().uri("/bff/superadmin/workloads/pods/app/pod-1/logs/stream")
                .accept(MediaType.TEXT_EVENT_STREAM)
                .exchange().expectStatus().isForbidden();
        verify(client, never()).streamLog(anyString(), anyString(), any());
    }

    @Test
    void stepUp_asAdmin_crossTier_isForbidden_andNeverMints() {
        filterAllowsEverything();
        asAdmin().post().uri("/bff/superadmin/workloads/step-up")
                .exchange().expectStatus().isForbidden();
        verify(stepUp, never()).mint(anyString(), anyString());
    }

    @Test
    void rolloutRestart_asAdmin_crossTier_isForbidden_andNeverDeletes() {
        filterAllowsEverything();
        asAdmin().post().uri("/bff/superadmin/workloads/pods/app/wl-1/rollout-restart")
                .exchange().expectStatus().isForbidden();
        verify(client, never()).deleteWorkloadPods(anyString(), anyString());
    }

    @Test
    void deletePod_asAdmin_crossTier_isForbidden_andNeverDeletes() {
        filterAllowsEverything();
        asAdmin().delete().uri("/bff/superadmin/workloads/pods/app/pod-1")
                .exchange().expectStatus().isForbidden();
        verify(client, never()).deletePod(anyString(), anyString());
    }

    @Test
    void lifecycle_asAdmin_crossTier_isForbidden_andNeverEmits() {
        filterAllowsEverything();
        asAdmin().post().uri("/bff/superadmin/workloads/lifecycle/app/wl-1/scale")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"replicas\":3}")
                .exchange().expectStatus().isForbidden();
        verify(gitops, never()).scale(anyString(), anyString(), anyInt(), any(), anyString());
    }

    @Test
    void putConfig_asAdmin_crossTier_isForbidden_andNeverWrites() {
        filterAllowsEverything();
        asAdmin().put().uri("/bff/superadmin/workloads/config/brandx")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"adminEnabled\":true,\"dangerousTierEnabled\":true}")
                .exchange().expectStatus().isForbidden();
        verify(admin, never()).putConfig(anyString(), anyBoolean(), anyBoolean(), anyString());
    }

    // ════════════════════════ MOD / USER -> 403 ═══════════════════════════════════════

    @Test
    void pods_asMod_isForbidden() {
        filterAllowsEverything();
        asMod().get().uri("/bff/superadmin/workloads/pods")
                .exchange().expectStatus().isForbidden();
        verify(reads, never()).listPodsAll(any());
    }

    @Test
    void pods_asUser_isForbidden() {
        filterAllowsEverything();
        asUser().get().uri("/bff/superadmin/workloads/pods")
                .exchange().expectStatus().isForbidden();
        verify(reads, never()).listPodsAll(any());
    }

    // ════════════════════════ unauthenticated -> 401 ══════════════════════════════════

    @Test
    void pods_unauthenticated_is401_andNeverReads() {
        filterAllowsEverything();
        web.get().uri("/bff/superadmin/workloads/pods")
                .exchange().expectStatus().isUnauthorized();
        verify(reads, never()).listPodsAll(any());
    }

    @Test
    void execReadOnly_unauthenticated_is401_andNeverExecs() {
        filterAllowsEverything();
        web.post().uri("/bff/superadmin/workloads/exec/app/pod-1")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"command\":[\"ls\"]}")
                .exchange().expectStatus().isUnauthorized();
        verify(exec, never()).execReadOnly(anyString(), anyString(), anyString(), any(), any());
    }

    // ════════════════════════ step-up: a non-stepped-up principal is denied ═══════════

    @Test
    void execReadOnly_superadmin_withoutStepUp_filterDenies_403_andNeverExecs() {
        // Even an authenticated SUPERADMIN is denied a DANGEROUS capability when the central
        // filter's WorkloadAuthorizationService refuses (e.g. no/expired step-up token). The
        // controller body NEVER runs. This is the real filter's STEP-1 deny — not an in-test
        // re-derivation: we drive decide(...) to forbidden and assert the 403 + never-exec.
        when(props.isEnabled()).thenReturn(true);
        when(props.namespaceAllowed(anyString())).thenReturn(true);
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(authz.decide(any(), any(), anyBoolean(), anyBoolean(), any()))
                .thenReturn(Mono.just(WorkloadAccessDecision.forbidden("step-up required")));

        asSuperadmin().post().uri("/bff/superadmin/workloads/exec/app/pod-1")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"command\":[\"ls\"]}")
                .exchange().expectStatus().isForbidden();
        verify(exec, never()).execReadOnly(anyString(), anyString(), anyString(), any(), any());
    }

    // ════════════════════════ per-stream isolation: out-of-allowlist ns -> 403 ════════

    @Test
    void streamLogs_superadmin_outOfAllowlistNamespace_filterDenies_403_andNeverStreams() {
        // SSE / per-job isolation: a caller cannot tail logs in a namespace outside the
        // curated app-tier allowlist (the filter's STEP-0b namespace gate, BEFORE any k8s
        // call). This is how the console refuses to read another tier's / datastore's job
        // stream. The deny is the real filter's; the k8s log client is NEVER invoked.
        when(props.isEnabled()).thenReturn(true);
        when(props.namespaceAllowed(eq("vault"))).thenReturn(false);   // out of allowlist
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());

        asSuperadmin().get().uri("/bff/superadmin/workloads/pods/vault/secret-pod/logs/stream")
                .accept(MediaType.TEXT_EVENT_STREAM)
                .exchange().expectStatus().isForbidden();
        verify(client, never()).streamLog(anyString(), anyString(), any());
    }

    @Test
    void deletePod_superadmin_outOfAllowlistNamespace_filterDenies_403_andNeverDeletes() {
        when(props.isEnabled()).thenReturn(true);
        when(props.namespaceAllowed(eq("kube-system"))).thenReturn(false);
        when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());

        asSuperadmin().delete().uri("/bff/superadmin/workloads/pods/kube-system/coredns")
                .exchange().expectStatus().isForbidden();
        verify(client, never()).deletePod(anyString(), anyString());
    }

    // Suppress unused-import style warning for PodSummary (kept for readers wiring reads).
    @SuppressWarnings("unused")
    private static PodSummary unusedPodRef() { return null; }
}
