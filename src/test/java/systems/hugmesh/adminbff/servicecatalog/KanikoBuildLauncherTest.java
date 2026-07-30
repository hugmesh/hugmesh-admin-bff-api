package systems.hugmesh.adminbff.servicecatalog;

import io.fabric8.kubernetes.api.model.batch.v1.Job;
import io.fabric8.kubernetes.api.model.batch.v1.JobCondition;
import io.fabric8.kubernetes.api.model.batch.v1.JobStatus;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.BatchAPIGroupDSL;
import io.fabric8.kubernetes.client.dsl.MixedOperation;
import io.fabric8.kubernetes.client.dsl.ScalableResource;
import io.fabric8.kubernetes.client.dsl.V1BatchAPIGroupDSL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.web.ApiException;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link KanikoBuildLauncher} — Fabric8 client chain is fully mocked via
 * Mockito; no real cluster is required. Covers:
 * <ul>
 *   <li>DOCKERFILE happy path: build() emits an image reference containing brand/serviceKey;</li>
 *   <li>ZIP source: build() errors immediately with a 400 containing "ZIP";</li>
 *   <li>DOCKERFILE build failure: Job status shows failed ≥ 1 → build() errors with
 *       {@link IllegalStateException}.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class KanikoBuildLauncherTest {

    private static final String NAMESPACE = "test-builds";
    private static final String REGISTRY  = "registry.test.example";

    // ── Mocks for the Fabric8 client chain ───────────────────────────────────

    @Mock KubernetesClient                                      k8s;
    @Mock BatchAPIGroupDSL                                      batchDsl;
    @Mock V1BatchAPIGroupDSL                                    v1BatchDsl;
    @SuppressWarnings("rawtypes")
    @Mock MixedOperation                                        jobsOp;
    @SuppressWarnings("rawtypes")
    @Mock MixedOperation                                        inNamespaceOp;
    @Mock ScalableResource<Job>                                 jobResource;

    private KanikoBuildLauncher launcher;

    @BeforeEach
    void setUp() {
        // Wire the mock chain: k8s.batch().v1().jobs().inNamespace(ns)
        when(k8s.batch()).thenReturn(batchDsl);
        when(batchDsl.v1()).thenReturn(v1BatchDsl);
        //noinspection unchecked
        when(v1BatchDsl.jobs()).thenReturn(jobsOp);

        // 4th arg = repo-host-allowlist CSV; empty = any valid host (matches default behaviour).
        launcher = new KanikoBuildLauncher(k8s, NAMESPACE, REGISTRY, "");
    }

    // ── 1. DOCKERFILE happy path ─────────────────────────────────────────────

    @Test
    void build_dockerfile_success_emitsImageRef_containingBrandAndService() {
        // Arrange: .load(...).create() returns a created Job; .withName().waitUntilCondition()
        // returns a Job with succeeded=1.
        Job createdJob = new Job();
        Job succeededJob = new Job();
        JobStatus status = new JobStatus();
        status.setSucceeded(1);
        succeededJob.setStatus(status);

        //noinspection unchecked
        when(jobsOp.inNamespace(NAMESPACE)).thenReturn(inNamespaceOp);
        //noinspection unchecked
        when(inNamespaceOp.load(any(java.io.InputStream.class))).thenReturn(jobResource);
        when(jobResource.create()).thenReturn(createdJob);
        //noinspection unchecked
        when(inNamespaceOp.withName(any())).thenReturn(jobResource);
        when(jobResource.waitUntilCondition(any(), anyLong(), eq(TimeUnit.MINUTES)))
                .thenReturn(succeededJob);

        ServiceSource source = new ServiceSource(
                ServiceSource.Kind.DOCKERFILE,
                "https://forgejo.test/acme/myservice",
                "deploy/",
                "main");

        // Act + Assert: the emitted image ref must contain both the brand and the serviceKey.
        StepVerifier.create(launcher.build("acme-test", "myservice", source))
                .assertNext(imageRef -> {
                    assertThat(imageRef).contains("acme-test");
                    assertThat(imageRef).contains("myservice");
                    assertThat(imageRef).startsWith(REGISTRY);
                })
                .verifyComplete();
    }

    // ── 2. ZIP source → immediate 400 ───────────────────────────────────────

    @Test
    void build_zipSource_errorsWithBadRequest_containingZip() {
        ServiceSource source = new ServiceSource(
                ServiceSource.Kind.ZIP,
                "https://forgejo.test/acme/myservice",
                null,
                null);

        // ZIP source must never reach the cluster — the error is emitted synchronously.
        StepVerifier.create(launcher.build("acme-test", "myservice", source))
                .expectErrorSatisfies(t -> {
                    assertThat(t).isInstanceOf(ApiException.class);
                    assertThat(t.getMessage()).containsIgnoringCase("ZIP");
                })
                .verify();
    }

    // ── 3. DOCKERFILE build failure ──────────────────────────────────────────

    @Test
    void build_dockerfile_jobFails_errorsWithIllegalStateException() {
        // Arrange: the Job is created successfully but waitUntilCondition returns a failed Job.
        Job createdJob = new Job();
        Job failedJob = new Job();
        JobStatus status = new JobStatus();
        status.setFailed(1);
        // Also set a Failed condition to exercise both isFailed() branches.
        JobCondition condition = new JobCondition();
        condition.setType("Failed");
        condition.setStatus("True");
        status.setConditions(List.of(condition));
        failedJob.setStatus(status);

        //noinspection unchecked
        when(jobsOp.inNamespace(NAMESPACE)).thenReturn(inNamespaceOp);
        //noinspection unchecked
        when(inNamespaceOp.load(any(java.io.InputStream.class))).thenReturn(jobResource);
        when(jobResource.create()).thenReturn(createdJob);
        //noinspection unchecked
        when(inNamespaceOp.withName(any())).thenReturn(jobResource);
        when(jobResource.waitUntilCondition(any(), anyLong(), eq(TimeUnit.MINUTES)))
                .thenReturn(failedJob);

        ServiceSource source = new ServiceSource(
                ServiceSource.Kind.DOCKERFILE,
                "https://forgejo.test/acme/myservice",
                null,
                "main");

        StepVerifier.create(launcher.build("acme-test", "myservice", source))
                .expectErrorSatisfies(t -> assertThat(t).isInstanceOf(IllegalStateException.class))
                .verify();
    }

    // ── Static predicate unit checks ─────────────────────────────────────────

    // ── YAML-injection regression (render-time guard) ────────────────────────

    @Test
    void build_yamlBreakoutInRepoUrl_errors_andNeverCreatesJob() {
        // No load()/create() is stubbed: the LAYER-2 RepoUrlValidator backstop must reject the
        // hostile repoUrl BEFORE the "git://"+repoUrl concat / template substitution / any
        // cluster call, so a poisoned manifest is never applied. The newline/quote breakout is
        // now caught at the structural layer (a 400 ApiException) rather than the yamlSafe
        // render-guard — earlier = better.
        ServiceSource source = new ServiceSource(
                ServiceSource.Kind.DOCKERFILE,
                "https://forgejo.test/acme/x\"\n            - \"--destination=evil.example/pwn",
                "deploy/",
                "main");

        StepVerifier.create(launcher.build("acme-test", "myservice", source))
                .expectErrorSatisfies(t -> {
                    assertThat(t).isInstanceOf(ApiException.class);
                    assertThat(t.getMessage()).containsIgnoringCase("repoUrl");
                })
                .verify();
    }

    @Test
    void build_ssrfMetadataRepoUrl_rejectedBeforeAnyClusterCall() {
        // A cloud-metadata SSRF URL (plaintext http + link-local IP) passes the charset @Pattern
        // but the LAYER-2 structural validator rejects the http scheme → 400, no Job created.
        ServiceSource source = new ServiceSource(
                ServiceSource.Kind.DOCKERFILE,
                "http://169.254.169.254/latest/meta-data/",
                "deploy/",
                "main");

        StepVerifier.create(launcher.build("acme-test", "myservice", source))
                .expectErrorSatisfies(t -> {
                    assertThat(t).isInstanceOf(ApiException.class);
                    assertThat(t.getMessage()).containsIgnoringCase("scheme");
                })
                .verify();
    }

    @Test
    void build_fileSchemeRepoUrl_rejectedBeforeAnyClusterCall() {
        // file:///etc/passwd (local-file-read SSRF) — rejected at the sink, no Job created.
        ServiceSource source = new ServiceSource(
                ServiceSource.Kind.DOCKERFILE,
                "file:///etc/passwd",
                "deploy/",
                "main");

        StepVerifier.create(launcher.build("acme-test", "myservice", source))
                .expectErrorSatisfies(t -> assertThat(t).isInstanceOf(ApiException.class))
                .verify();
    }

    @Test
    void build_hostlessRepoUrl_rejectedBeforeAnyClusterCall() {
        // git:// with no host — rejected at the sink, no Job created.
        ServiceSource source = new ServiceSource(
                ServiceSource.Kind.DOCKERFILE,
                "git://",
                "deploy/",
                "main");

        StepVerifier.create(launcher.build("acme-test", "myservice", source))
                .expectErrorSatisfies(t -> assertThat(t).isInstanceOf(ApiException.class))
                .verify();
    }

    @Test
    void build_yamlBreakoutInTargetRevision_errors() {
        ServiceSource source = new ServiceSource(
                ServiceSource.Kind.DOCKERFILE,
                "https://forgejo.test/acme/myservice",
                "deploy/",
                "HEAD\"\n            - \"--build-arg=PWNED=1");

        StepVerifier.create(launcher.build("acme-test", "myservice", source))
                .expectErrorSatisfies(t -> assertThat(t).isInstanceOf(IllegalStateException.class))
                .verify();
    }

    @Test
    void yamlSafe_passesCleanGitContext_rejectsQuoteAndNewline() {
        // A legitimate git:// context with branch/path passes unchanged.
        String clean = "git://https://forgejo.test/acme/myservice#main";
        assertThat(KanikoBuildLauncher.yamlSafe("context", clean)).isEqualTo(clean);

        assertThat(catchThrowable(() -> KanikoBuildLauncher.yamlSafe("context", "a\"b")))
                .isInstanceOf(IllegalStateException.class);
        assertThat(catchThrowable(() -> KanikoBuildLauncher.yamlSafe("context", "a\nb")))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void isSucceeded_falseWhenNull() {
        assertThat(KanikoBuildLauncher.isSucceeded(null)).isFalse();
    }

    @Test
    void isFailed_trueOnFailedCondition() {
        Job job = new Job();
        JobStatus status = new JobStatus();
        JobCondition c = new JobCondition();
        c.setType("Failed");
        c.setStatus("True");
        status.setConditions(List.of(c));
        job.setStatus(status);
        assertThat(KanikoBuildLauncher.isFailed(job)).isTrue();
    }

    @Test
    void isTerminal_trueWhenSucceeded() {
        Job job = new Job();
        JobStatus status = new JobStatus();
        status.setSucceeded(1);
        job.setStatus(status);
        assertThat(KanikoBuildLauncher.isTerminal(job)).isTrue();
    }
}
