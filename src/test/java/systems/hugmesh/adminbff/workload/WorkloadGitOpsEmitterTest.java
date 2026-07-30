package systems.hugmesh.adminbff.workload;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.security.PrincipalDomain;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The GitOps-PR intent emitter — proves the deploy provenance gate (DECISION 7: digest-pinned
 * own-registry only; a tag-only ref is rejected at PR-gen time) and that every verb records a
 * pending intent.
 */
class WorkloadGitOpsEmitterTest {

    private final WorkloadConsoleIntentRepository intents = mock(WorkloadConsoleIntentRepository.class);
    private final WorkloadGitOpsEmitter emitter = new WorkloadGitOpsEmitter(intents);
    private final PrincipalDomain scope = WorkloadScopeFixtures.superadminScope();

    @Test
    void deploy_rejectsTagOnlyImage() {
        StepVerifier.create(emitter.deploy("ns", "wl", "registry.local/app:latest", scope, "root"))
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    void deploy_acceptsDigestPinnedImage() {
        when(intents.maxGeneration()).thenReturn(Mono.just(0L));
        when(intents.insert(any(), anyLong())).thenAnswer(inv ->
                Mono.just(inv.getArgument(0, WorkloadConsoleIntent.class)));
        String digest = "registry.local/app@sha256:" + "a".repeat(64);
        StepVerifier.create(emitter.deploy("ns", "wl", digest, scope, "root"))
                .assertNext(i -> {
                    org.assertj.core.api.Assertions.assertThat(i.kind())
                            .isEqualTo(WorkloadConsoleIntent.KIND_DEPLOY);
                    org.assertj.core.api.Assertions.assertThat(i.imageRef()).isEqualTo(digest);
                })
                .verifyComplete();
    }

    @Test
    void requireDigest_staticGuard() {
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> WorkloadGitOpsEmitter.requireDigest("nginx:1.25"))
                .isInstanceOf(IllegalArgumentException.class);
        // does not throw on a digest-pinned ref
        WorkloadGitOpsEmitter.requireDigest("repo@sha256:" + "b".repeat(64));
    }
}
