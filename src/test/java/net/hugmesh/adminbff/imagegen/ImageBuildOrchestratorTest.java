package net.hugmesh.adminbff.imagegen;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.sshterminal.ImageBuild;
import net.hugmesh.adminbff.sshterminal.ImageBuildRepository;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.web.dto.ImageBuildProgressRequest;

import net.hugmesh.adminbff.support.SubscribingThread;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Orchestrator behaviour against the REAL H2 repo (durable image_build writes genuinely
 * exercised), with a fake {@link ImageJobLauncher} standing in for the cluster:
 * <ul>
 *   <li>launch → the build goes RUNNING + emits a launch SSE event + the rendered manifest is
 *       fully substituted (no leftover {@code ${...}});</li>
 *   <li>a terminal COMPLETED ingest → closes the build COMPLETED + emits the terminal SSE event
 *       (carrying the NON-SECRET image/keys pointers) + completes the sink;</li>
 *   <li>a failing launcher → the build is ERRORed (inconclusive), not a crash.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, ImageBuildRepository.class})
class ImageBuildOrchestratorTest {

    @Autowired ImageBuildRepository repo;

    static final class CapturingLauncher implements ImageJobLauncher {
        final List<String> manifests = new ArrayList<>();
        private final boolean real;
        private final RuntimeException boom;
        CapturingLauncher(boolean real, RuntimeException boom) { this.real = real; this.boom = boom; }
        @Override public Mono<String> apply(String manifest, String buildId) {
            return Mono.fromCallable(() -> {
                manifests.add(manifest);
                if (boom != null) throw boom;
                return "hugmesh-image-gen-" + buildId;
            });
        }
        @Override public boolean isReal() { return real; }
    }

    private ImageBuildOrchestrator orchestrator(ImageJobLauncher launcher) {
        return new ImageBuildOrchestrator(repo, launcher, 64);
    }

    private ImageBuild queued() {
        return repo.insert(new ImageBuild(null, null, "admin@x", "brandx/alice", "brandx",
                ImageBuild.IMAGE_PRIMARY, "rpi5", null, ImageBuild.STATUS_QUEUED, true,
                null, null, null, null, null, null)).block();
    }

    @Test
    void launch_marksRunning_andSubstitutesTemplate() {
        CapturingLauncher launcher = new CapturingLauncher(true, null);
        ImageBuildOrchestrator orch = orchestrator(launcher);
        assertThat(orch.launchIsReal()).isTrue();

        ImageBuild build = queued();
        orch.launch(build).block();

        ImageBuild after = repo.findById(build.id()).block();
        assertThat(after.status()).isEqualTo(ImageBuild.STATUS_RUNNING);
        assertThat(launcher.manifests).hasSize(1);
        String m = launcher.manifests.get(0);
        assertThat(m).contains(build.id()).contains("primary").contains("rpi5")
                .doesNotContain("${BUILD_ID}").doesNotContain("${IMAGE_TYPE}")
                .doesNotContain("${HARDWARE_CLASS}");
    }

    @Test
    void ingestCompleted_closesBuild_emitsPointers_completesSink() {
        ImageBuildOrchestrator orch = orchestrator(new CapturingLauncher(false, null));
        ImageBuild build = queued();
        orch.launch(build).block();

        orch.ingest(build.id(), ImageBuild.STATUS_COMPLETED,
                "build-" + build.id() + "/image.img", "build-" + build.id() + "/keys.tar.gz",
                "done", null).block();

        ImageBuild done = repo.findById(build.id()).block();
        assertThat(done.status()).isEqualTo(ImageBuild.STATUS_COMPLETED);

        // the sink is completed and the terminal event carries the non-secret pointers.
        StepVerifier.create(orch.events(build.id()).collectList())
                .assertNext(events -> {
                    assertThat(events).anyMatch(ImageBuildEvent::done);
                    String expectedRef = "build-" + build.id() + "/image.img";
                    assertThat(events).anyMatch(e -> expectedRef.equals(e.imageRef()));
                })
                .verifyComplete();
    }

    // ── NON-TERMINAL progress leg (item 8): progress frames precede the single terminal ──
    @Test
    void progress_emitsNonTerminalFrames_thenTerminalClosesSink() {
        ImageBuildOrchestrator orch = orchestrator(new CapturingLauncher(false, null));
        ImageBuild build = queued();
        orch.launch(build).block();                       // creates the sink + a launch progress(0)

        // 0..N non-terminal progress posts (done=false), sink stays OPEN.
        orch.progress(build.id(), 20, "partition", "partitioning disk").block();
        orch.progress(build.id(), 60, "package", "installing packages").block();

        // the single terminal ingest closes the sink.
        orch.ingest(build.id(), ImageBuild.STATUS_COMPLETED,
                "build-" + build.id() + "/image.img", null, "done", null).block();

        StepVerifier.create(orch.events(build.id()).collectList())
                .assertNext(events -> {
                    // at least the launch progress + the two explicit progress frames are non-terminal
                    long nonTerminal = events.stream().filter(e -> !e.done()).count();
                    assertThat(nonTerminal).isGreaterThanOrEqualTo(3);
                    // exactly one terminal frame, and it is LAST (progress never closed the sink early)
                    long terminal = events.stream().filter(ImageBuildEvent::done).count();
                    assertThat(terminal).isEqualTo(1);
                    assertThat(events.get(events.size() - 1).done()).isTrue();
                    // a mid-build progress frame carries its phase + percent (done=false)
                    assertThat(events).anyMatch(e -> !e.done() && "partition".equals(e.phase()) && e.percent() == 20);
                })
                .verifyComplete();
    }

    @Test
    void progress_onUnknownBuild_isNoOp() {
        ImageBuildOrchestrator orch = orchestrator(new CapturingLauncher(false, null));
        // no sink for this id — a reaped/unknown build progress post is a silent no-op, never a throw.
        orch.progress("no-such-build", 10, "kernel", "compiling").block();
        StepVerifier.create(orch.events("no-such-build").collectList())
                .assertNext(events -> assertThat(events).isEmpty())
                .verifyComplete();
    }

    // ── the REAL /progress wire contract (ImageBuildService.progress -> orchestrator -> SSE) ──
    // The worker (docker/progress-tap.py) never sends percent/phase/message: it sends
    // buildId/percent(nullable)/phaseIndex/phaseCount/phaseLabel/indeterminate. This test drives
    // the ACTUAL ImageBuildService.progress() mapping (not a hand-rolled orchestrator call) so a
    // regression in that mapping is caught here, and proves the mapped frame reaches a live SSE
    // subscriber, exactly like ImageBuildOrchestratorTest's other progress/ingest assertions.
    @Test
    void serviceProgress_mapsRealWorkerShape_ontoSse_forInFlightBuild() {
        ImageBuildOrchestrator orch = orchestrator(new CapturingLauncher(false, null));
        ImageBuildService service = new ImageBuildService(repo, /*dials*/ null, /*devices*/ null,
                orch, /*artifacts*/ null, /*stepUp*/ null, /*mfaStepUp*/ null, /*domainRegistry*/ null,
                new WorklistEnvelopeValidator(), new ImageGenConfig());
        ImageBuild build = queued();
        orch.launch(build).block();   // creates the sink + the initial launch progress(0) frame

        // 1) the INITIAL indeterminate frame progress-tap.py sends before any "==>" banner: percent
        //    is null, phaseIndex=-1, phaseLabel="" — must map to the honest lower bound (percent=0,
        //    phase falls back to PHASE_RUNNING), never crash, never fabricate a percent.
        service.progress(build.id(), new ImageBuildProgressRequest(null, -1, 18, "", true)).block();

        // 2) a determinate mid-build frame: percent=42, phase 6 of 18, label "Emerge packages".
        service.progress(build.id(),
                new ImageBuildProgressRequest(42, 5, 18, "Emerge packages", false)).block();

        // Close the sink with the single terminal ingest (as the real flow does) so the replay
        // Flux completes and collectList() terminates — this ALSO proves the two service.progress
        // frames above did NOT close the sink early (the terminal is still the sole closer).
        orch.ingest(build.id(), ImageBuild.STATUS_COMPLETED,
                "build-" + build.id() + "/image.img", null, "done", null).block();

        StepVerifier.create(orch.events(build.id()).collectList())
                .assertNext(events -> {
                    // exactly one terminal frame, and it is LAST — the two mapped progress frames
                    // (and the launch frame) were all non-terminal and never closed the sink early.
                    assertThat(events.stream().filter(ImageBuildEvent::done).count()).isEqualTo(1);
                    assertThat(events.get(events.size() - 1).done()).isTrue();
                    // the indeterminate frame's null percent honestly maps to 0, not a fabricated value.
                    assertThat(events).anyMatch(e -> !e.done() && e.percent() == 0
                            && ImageBuildEvent.PHASE_RUNNING.equals(e.phase()));
                    // the determinate frame's percent + human phase label both ride through untouched.
                    assertThat(events).anyMatch(e -> !e.done() && e.percent() == 42
                            && "Emerge packages".equals(e.phase())
                            && e.message() != null && e.message().contains("6/18"));
                })
                .verifyComplete();
    }

    // ── YAML-injection regression (render-time guard, no DB / no cluster) ─────

    /** Build an in-memory ImageBuild row with the given attacker/legit values for render tests. */
    private static ImageBuild buildWith(String targetUser, String hardwareClass) {
        return new ImageBuild("00000000-0000-0000-0000-000000000001", null, "admin@x",
                targetUser, "brandx", ImageBuild.IMAGE_PRIMARY, hardwareClass, null,
                ImageBuild.STATUS_QUEUED, true, null, null, null, null, null, null);
    }

    @Test
    void renderManifest_legitTargetUser_substitutesCleanly() {
        ImageBuildOrchestrator orch = orchestrator(new CapturingLauncher(false, null));

        ImageBuild build = buildWith("brandx/alice", "rpi5");
        String manifest = orch.renderManifest(build);

        // The legit value is present, the placeholders are gone, and the YAML is intact.
        assertThat(manifest).contains("brandx/alice").contains("rpi5")
                .doesNotContain("${TARGET_USER}").doesNotContain("${HARDWARE_CLASS}");
    }

    // Sibling of INGEST_URL — PROGRESS_URL is a fully-static templated string in
    // jobs/image-gen-job.yaml (no dedicated ${...} placeholder or renderManifest code path of its
    // own); it rides the SAME generic ${BUILD_ID} substitution pass INGEST_URL already relies on,
    // so this proves that substitution reaches PROGRESS_URL too.
    @Test
    void renderManifest_substitutesBuildIdIntoBothIngestAndProgressUrls() {
        ImageBuildOrchestrator orch = orchestrator(new CapturingLauncher(false, null));
        ImageBuild build = buildWith("brandx/alice", "rpi5");

        String manifest = orch.renderManifest(build);

        String base = "https://hugmesh-admin-bff-api.hugmesh-backend.svc.cluster.local:8443"
                + "/bff/internal/image-builds/" + build.id();
        assertThat(manifest)
                .contains("name: INGEST_URL")
                .contains(base + "/ingest")
                .contains("name: PROGRESS_URL")
                .contains(base + "/progress")
                .doesNotContain("${BUILD_ID}");
    }

    @Test
    void renderManifest_yamlBreakoutInTargetUser_isRejected() {
        ImageBuildOrchestrator orch = orchestrator(new CapturingLauncher(false, null));
        // A payload that closes the quoted scalar + flow map and injects a sibling env item.
        String exploit = "x\"}\n        - {name: EVIL, value: \"y";

        assertThatThrownBy(() -> orch.renderManifest(buildWith(exploit, "rpi5")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("targetUser");
    }

    @Test
    void renderManifest_yamlBreakoutInHardwareClass_isRejected() {
        ImageBuildOrchestrator orch = orchestrator(new CapturingLauncher(false, null));

        assertThatThrownBy(() ->
                orch.renderManifest(buildWith("brandx/alice", "rpi5\"\n    privileged: true")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hardwareClass");
    }

    @Test
    void launch_launcherThrows_marksErrorNotCrash() {
        ImageBuildOrchestrator orch = orchestrator(
                new CapturingLauncher(true, new RuntimeException("cluster says no")));
        ImageBuild build = queued();

        orch.launch(build).block(Duration.ofSeconds(5));   // returns normally (error not propagated)
        ImageBuild after = repo.findById(build.id()).block();
        assertThat(after.status()).isEqualTo(ImageBuild.STATUS_ERROR);
    }

    /**
     * renderManifest is NOT pure string templating: it re-reads {@code jobs/image-gen-job.yaml}
     * out of the app jar on EVERY call ({@code ClassPathResource#getInputStream}, uncached), so
     * it is blocking I/O. In production {@code launch()} is subscribed from an R2DBC/Netty event
     * loop ({@code ImageBuildService}:
     * {@code builds.insert(queued).flatMap(b -> orchestrator.launch(b).thenReturn(b))}), so the
     * render needs its OWN boundedElastic offload — the launcher seam's offload only covers the
     * fabric8 round-trip that happens after it, and cannot retroactively move the render.
     */
    @Test
    void launch_rendersTheManifestOffTheSubscribingThread() {
        AtomicReference<String> renderThread = new AtomicReference<>();
        ImageBuildOrchestrator orch = new ImageBuildOrchestrator(
                repo, new CapturingLauncher(true, null), 64) {
            @Override
            String renderManifest(ImageBuild b) {
                renderThread.set(Thread.currentThread().getName());
                return super.renderManifest(b);
            }
        };
        ImageBuild build = queued();

        SubscribingThread.runExpectingSuccess(() -> orch.launch(build).block(Duration.ofSeconds(30)));

        assertThat(renderThread.get())
                .as("the classpath read in renderManifest must not run on the subscribing "
                        + "(R2DBC/Netty) thread")
                .isNotEqualTo(SubscribingThread.NAME)
                .startsWith("boundedElastic-");
    }
}
