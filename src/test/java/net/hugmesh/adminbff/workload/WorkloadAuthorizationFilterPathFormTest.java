package net.hugmesh.adminbff.workload;

import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The workload-console gate (feature gate, namespace allowlist, danger tier, step-up) is keyed
 * on the path the ROUTER resolves, not on the raw request string. Every spelling below is one
 * the router decodes to the same controller method as the plain form, so each must be gated
 * EXACTLY like the plain form: 404 when the generator gate is off, 403 for a namespace outside
 * the allowlist, 403 for a DANGEROUS tier without step-up, and the guarded body never runs.
 * Before the fix a percent-encoded spelling (for example {@code /bff/admin/%77orkloads/...} or
 * {@code /bff/superadmin/workloads/%65xec/...}) skipped the filter entirely and reached the
 * controller with only the role gate in front of it.
 *
 * <p>Driven through the REAL {@link SecurityConfig} (role gate, firewall) as a SUPERADMIN,
 * the principal for whom the role gate alone would let everything through.
 */
@WebFluxTest(controllers = {WorkloadAdminController.class, WorkloadSuperadminController.class})
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class WorkloadAuthorizationFilterPathFormTest {

    @Autowired ApplicationContext context;
    WebTestClient web;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        lenient().when(props.isEnabled()).thenReturn(true);
        lenient().when(props.namespaceAllowed(anyString())).thenReturn(false);
        lenient().when(props.namespaceAllowed(eq("app"))).thenReturn(true);
        lenient().when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        lenient().when(authz.decide(any(), any(), anyBoolean(), anyBoolean(), any()))
                .thenAnswer(inv -> Mono.just(inv.getArgument(1) == DangerTier.DANGEROUS
                        ? WorkloadAccessDecision.forbidden("step-up required")
                        : WorkloadAccessDecision.allow(true, true)));
        lenient().when(reads.listPods(anyString(), any())).thenReturn(Flux.empty());
        lenient().when(reads.listPodsAll(any())).thenReturn(Flux.empty());
        lenient().when(exec.execReadOnly(anyString(), anyString(), anyString(), any(), any()))
                .thenReturn(Mono.just(new WorkloadDtos.ExecResult(0, "ok", "")));
    }

    @MockitoBean WorkloadReadService reads;
    @MockitoBean WorkloadConsoleAdminService admin;
    @MockitoBean WorkloadGitOpsEmitter gitops;
    @MockitoBean WorkloadExecService exec;
    @MockitoBean WorkloadStepUpService stepUp;
    @MockitoBean WorkloadClient client;
    @MockitoBean WorkloadConsoleProperties props;
    @MockitoBean WorkloadConsoleIntentRepository intents;
    @MockitoBean WorkloadAuthorizationService authz;
    @MockitoBean UsageService usage;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient superadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject("s"))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private void expect(HttpMethod m, String uri, int status) {
        superadmin().method(m).uri(URI.create(uri))
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"command\":[\"ls\"]}")
                .exchange().expectStatus().isEqualTo(status);
    }

    private void bodiesNeverRan() {
        verify(reads, never()).listPods(anyString(), any());
        verify(reads, never()).listPodsAll(any());
        verify(exec, never()).execReadOnly(anyString(), anyString(), anyString(), any(), any());
        verify(gitops, never()).scale(anyString(), anyString(), anyInt(), any(), anyString());
    }

    // ───────── namespace allowlist (STEP 0b): vault is NOT allowlisted ─────────

    @ParameterizedTest(name = "[{index}] GET {0} -> 403")
    @ValueSource(strings = {
            "/bff/admin/workloads/pods/vault",                    // control: the plain spelling
            "/bff/admin/%77orkloads/pods/vault",                  // encoded prefix segment
            "/bff/admin/work%6Coads/pods/vault",
            "/bff/%61dmin/workloads/pods/vault",
            "/%62ff/%61dmin/%77orkloads/pods/vault",
            "/bff/admin/workloads/p%6Fds/vault",                  // encoded family keyword
            "/bff/admin/workloads/pods/v%61ult",                  // encoded namespace
            "/bff/admin/workloads/pods/vault/",                   // trailing slash
            "/bff/admin/workloads//pods/vault",                   // empty segment
            "/bff/admin/workloads/pods/app%2Fx",                  // %2F stays INSIDE the ns segment
            "/bff/superadmin/%77orkloads/pods/vault",
    })
    void encodedSpellings_areGatedByNamespaceAllowlist(String uri) {
        expect(HttpMethod.GET, uri, 403);
        bodiesNeverRan();
    }

    @Test
    void allowlistedNamespace_stillReachesTheController_inEveryEncodedSpelling() {
        expect(HttpMethod.GET, "/bff/admin/workloads/pods/app", 200);
        expect(HttpMethod.GET, "/bff/admin/%77orkloads/pods/app", 200);
        expect(HttpMethod.GET, "/bff/admin/workloads/p%6Fds/%61pp", 200);
        verify(reads, times(3)).listPods(eq("app"), any());
    }

    // ───────── DANGEROUS tier without step-up: authz refuses DANGEROUS ─────────

    @ParameterizedTest(name = "[{index}] POST {0} -> 403")
    @ValueSource(strings = {
            "/bff/superadmin/workloads/exec/app/pod-1",           // control
            "/bff/superadmin/workloads/%65xec/app/pod-1",         // encoded tier keyword
            "/bff/superadmin/workloads/ex%65c/app/pod-1",
            "/bff/superadmin/%77orkloads/exec/app/pod-1",
            "/bff/%73uperadmin/workloads/exec/app/pod-1",
            "/bff/superadmin/workloads/exec/app/pod-1/",
            "/bff/superadmin/workloads//exec/app/pod-1",
            "/bff/superadmin/workloads/%65xec/%61pp/pod-1",
    })
    void encodedDangerousSpellings_areDeniedWithoutStepUp(String uri) {
        expect(HttpMethod.POST, uri, 403);
        bodiesNeverRan();
    }

    @Test
    void encodedLifecycle_isDeniedWithoutStepUp() {
        expect(HttpMethod.POST, "/bff/superadmin/workloads/lifecycle/app/wl-1/scale", 403);
        expect(HttpMethod.POST, "/bff/superadmin/workloads/%6Cifecycle/app/wl-1/scale", 403);
        expect(HttpMethod.POST, "/bff/superadmin/%77orkloads/%6Cifecycle/app/wl-1/scale", 403);
        bodiesNeverRan();
    }

    // ───────── generator gate OFF: the whole prefix does not exist (404) ─────────

    @ParameterizedTest(name = "[{index}] gate off, GET {0} -> 404")
    @ValueSource(strings = {
            "/bff/admin/workloads/capability",                    // control
            "/bff/admin/%77orkloads/capability",
            "/bff/admin/workloads/%63apability",
            "/bff/superadmin/%77orkloads/pods",
            "/bff/superadmin/workloads/p%6Fds",
    })
    void generatorGateOff_encodedSpellingsAre404(String uri) {
        when(props.isEnabled()).thenReturn(false);
        expect(HttpMethod.GET, uri, 404);
        bodiesNeverRan();
    }
}
