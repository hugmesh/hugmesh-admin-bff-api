package net.hugmesh.adminbff.workload;

import net.hugmesh.adminbff.usage.UsageService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.PathContainer;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Drives {@link WorkloadAuthorizationFilter} DIRECTLY (no Spring Security firewall in front,
 * which would answer 400 to several of these spellings by itself and so hide the filter), to
 * pin the classification of the spellings the HTTP-level test cannot reach: matrix parameters,
 * dot segments, case, double encoding, and the namespace taken from the wrong place.
 */
class WorkloadAuthorizationFilterSegmentsTest {

    WorkloadConsoleProperties props = mock(WorkloadConsoleProperties.class);
    WorkloadAuthorizationService authz = mock(WorkloadAuthorizationService.class);
    UsageService usage = mock(UsageService.class);
    WorkloadAuthorizationFilter filter;

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> provider(T t) {
        ObjectProvider<T> p = mock(ObjectProvider.class);
        lenient().when(p.getIfAvailable()).thenReturn(t);
        return p;
    }

    @BeforeEach
    void setUp() {
        lenient().when(props.isEnabled()).thenReturn(true);
        lenient().when(props.namespaceAllowed(anyString())).thenReturn(false);
        lenient().when(props.namespaceAllowed(eq("app"))).thenReturn(true);
        lenient().when(usage.record(anyString(), any(), anyString())).thenReturn(Mono.empty());
        // The predicate ALLOWS everything: only the filter's own path classification can refuse.
        lenient().when(authz.decide(any(), any(), anyBoolean(), anyBoolean(), any()))
                .thenReturn(Mono.just(WorkloadAccessDecision.allow(true, true)));
        filter = new WorkloadAuthorizationFilter(provider(props), provider(authz), provider(usage));
    }

    private record Result(HttpStatus status, boolean chained) { }

    private Result run(HttpMethod m, String uri) {
        MockServerWebExchange ex = MockServerWebExchange.from(
                MockServerHttpRequest.method(m, URI.create(uri)).build());
        AtomicBoolean chained = new AtomicBoolean();
        filter.filter(ex, e -> { chained.set(true); return Mono.empty(); }).block();
        var code = ex.getResponse().getStatusCode();
        return new Result(code == null ? null : HttpStatus.valueOf(code.value()), chained.get());
    }

    private void assertRefused(HttpMethod m, String uri, HttpStatus status) {
        Result r = run(m, uri);
        assertThat(r.chained()).as("%s %s must not reach the controller", m, uri).isFalse();
        assertThat(r.status()).as("%s %s", m, uri).isEqualTo(status);
    }

    // ───────── the exploit: encoded prefix is not a different path ─────────

    @Test
    void encodedPrefix_isNotSkipped_gateOffIs404() {
        when(props.isEnabled()).thenReturn(false);
        assertRefused(HttpMethod.GET, "/bff/admin/%77orkloads/capability", HttpStatus.NOT_FOUND);
        assertRefused(HttpMethod.GET, "/bff/superadmin/%77orkloads/pods", HttpStatus.NOT_FOUND);
    }

    // ───────── spellings ─────────

    @ParameterizedTest
    @ValueSource(strings = {
            "/bff/admin/workloads;x=1/pods/vault",          // matrix param on the prefix segment
            "/bff/admin/workloads/pods;x=1/vault",          // ... on the family keyword
            "/bff/admin/workloads/pods/vault;x=1",          // ... on the namespace segment
            "/bff/admin/workloads/pods/vault;x=1;y=2/",
            "/bff/admin/Workloads/pods/vault",              // case
            "/BFF/Admin/WORKLOADS/pods/vault",
            "/bff/admin/workloads/PODS/vault",
            "/bff/admin/workloads//pods/vault",             // empty segment
            "/bff/admin/workloads/pods//vault",
            "/bff/admin/workloads/pods/vault/",             // trailing slash
            "/bff/admin/%77orkloads/pods/vault",            // single encoding
            "/bff/admin/workloads/p%6Fds/%76ault",
    })
    void namespaceGate_appliesInEverySpelling(String uri) {
        assertRefused(HttpMethod.GET, uri, HttpStatus.FORBIDDEN);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/bff/admin/workloads/pods/app/..",             // dot segments: refused, not guessed at
            "/bff/admin/workloads/pods/app/.",
            "/bff/admin/workloads/./pods/app",
            "/bff/admin/./workloads/pods/app",
            "/bff/admin/x/../workloads/pods/vault",
            "/bff/admin/workloads/pods/vault/../app",
            "/bff/admin/workloads/pods/%2e%2e/vault",
            "/bff/admin/workloads/pods/%2E/app",
            "/bff/admin/workloads/../../admin/workloads/pods/vault",
    })
    void dotSegments_inAConsolePath_areRefused(String uri) {
        assertRefused(HttpMethod.GET, uri, HttpStatus.BAD_REQUEST);
    }

    @Test
    void dotSegments_resolvingIntoTheConsole_areStillConsolePaths() {
        // a normalising hop would forward this as /bff/superadmin/workloads/exec/...
        assertRefused(HttpMethod.POST, "/bff/superadmin/x/../workloads/exec/app/pod-1",
                HttpStatus.BAD_REQUEST);
    }

    @Test
    void doubleEncoding_isDecodedExactlyOnce() {
        // %2576ault -> the literal "%76ault" (what the controller binds); never decoded again
        // to "vault" and never compared as if it were "app".
        assertRefused(HttpMethod.GET, "/bff/admin/workloads/pods/%2576ault", HttpStatus.FORBIDDEN);
        verify(props).namespaceAllowed("%76ault");
        // "app" spelled with one level of escaping is the allowlisted namespace...
        assertThat(run(HttpMethod.GET, "/bff/admin/workloads/pods/%61pp").chained()).isTrue();
        // ... but with two levels it is the literal "%61pp", which is not.
        assertRefused(HttpMethod.GET, "/bff/admin/workloads/pods/%2561pp", HttpStatus.FORBIDDEN);
        verify(props).namespaceAllowed("%61pp");
    }

    @Test
    void doubleEncodedPrefix_isNotAConsolePath_andIsNotInvented() {
        // %2577orkloads decodes once to the literal "%77orkloads": no controller routes it, and
        // the filter must not decode it a second time into the console prefix either way.
        assertThat(run(HttpMethod.GET, "/bff/admin/%2577orkloads/pods/vault").chained()).isTrue();
    }

    // ───────── namespace is taken from the position the router binds it ─────────

    @Test
    void namespaceIsPositional_notFoundAnywhereInThePath() {
        // controller: lifecycle/{ns=vault}/{workload=pods}/{verb=app}. The old regex search
        // found "/pods/app" later in the path and gated "app" (allowed) instead of "vault".
        assertRefused(HttpMethod.POST, "/bff/superadmin/workloads/lifecycle/vault/pods/app",
                HttpStatus.FORBIDDEN);
        verify(props).namespaceAllowed("vault");
    }

    @Test
    void execTtyHandshake_namespaceIsGated() {
        assertRefused(HttpMethod.GET, "/bff/superadmin/workloads/exec-tty/vault/pod-1",
                HttpStatus.FORBIDDEN);
        assertThat(run(HttpMethod.GET, "/bff/superadmin/workloads/exec-tty/app/pod-1").chained())
                .isTrue();
    }

    @Test
    void unrelatedPaths_passThrough() {
        assertThat(run(HttpMethod.GET, "/bff/admin/users").chained()).isTrue();
        assertThat(run(HttpMethod.GET, "/bff/admin").chained()).isTrue();
        assertThat(run(HttpMethod.GET, "/actuator/health").chained()).isTrue();
    }

    // ───────── classifier on the segment list ─────────

    private static List<String> segs(String path) {
        return WorkloadPathClassifier.segmentsOf(PathContainer.parsePath(path));
    }

    @Test
    void segmentsAreDecodedOnce_withParametersStripped() {
        assertThat(segs("/bff/admin/%77orkloads;a=b/pods/v%61ult;c"))
                .containsExactly("bff", "admin", "workloads", "pods", "vault");
        assertThat(segs("/a//b/")).containsExactly("a", "b");
        assertThat(segs("/pods/a%2Fb")).containsExactly("pods", "a/b");
        assertThat(segs("/pods/%2561")).containsExactly("pods", "%61");
    }

    @Test
    void tierFollowsTheDecodedCaseFoldedPath() {
        assertThat(WorkloadPathClassifier.tierOf(
                segs("/bff/superadmin/workloads/%45XEC/app/p"), HttpMethod.POST))
                .isEqualTo(DangerTier.DANGEROUS);
        assertThat(WorkloadPathClassifier.tierOf(
                segs("/bff/superadmin/workloads/pods/app/wl/rollout-%72estart"), HttpMethod.POST))
                .isEqualTo(DangerTier.RUNTIME_MUTATE);
        assertThat(WorkloadPathClassifier.tierOf(
                segs("/bff/superadmin/workloads/p%6Fds/app/p"), HttpMethod.DELETE))
                .isEqualTo(DangerTier.RUNTIME_MUTATE);
        assertThat(WorkloadPathClassifier.tierOf(
                segs("/bff/admin/workloads/pods/app"), HttpMethod.GET)).isEqualTo(DangerTier.READ);
        assertThat(WorkloadPathClassifier.isLogPath(segs("/bff/admin/workloads/pods/app/p/l%6Fgs")))
                .isTrue();
    }
}
