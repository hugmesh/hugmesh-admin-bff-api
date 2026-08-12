package net.hugmesh.adminbff.platform;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.iso.IsoArtifact;
import net.hugmesh.adminbff.iso.IsoRepository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Data/flag/fail-safe REFLECTION for the controller, exercised directly (a FRESH controller per
 * case so the per-instance TTL cache cannot leak one case's reading into the next — the
 * {@code @WebFluxTest} slice shares a singleton controller, so it asserts authz only). The
 * {@code @Value} config-flag fields are seeded by reflection, mirroring {@code AnubisControllerTest}.
 */
class PlatformCapabilitiesControllerDataTest {

    private static PlatformCapabilitiesController controller(
            PlatformCapabilityProbe probe, IsoRepository iso,
            boolean anubis, boolean forum, boolean testLaunch, boolean casdoor, boolean homeserver) {
        PlatformCapabilitiesController c = new PlatformCapabilitiesController(probe, iso);
        set(c, "anubisEnabled", anubis);
        set(c, "forumEnabled", forum);
        set(c, "testLaunchEnabled", testLaunch);
        set(c, "casdoorAdminEnabled", casdoor);
        set(c, "homeserverAdminEnabled", homeserver);
        return c;
    }

    private static void set(Object target, String field, boolean value) {
        try {
            var f = PlatformCapabilitiesController.class.getDeclaredField(field);
            f.setAccessible(true);
            f.setBoolean(target, value);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    private static IsoRepository isoWith(boolean present) {
        IsoRepository iso = mock(IsoRepository.class);
        when(iso.list()).thenReturn(
                present ? Flux.just(new IsoArtifact("pi.img", "https://x/pi.img")) : Flux.empty());
        return iso;
    }

    private static PlatformCapabilityProbe probeWith(boolean argocd, boolean velero,
                                                     boolean buildNode, List<String> warnings) {
        PlatformCapabilityProbe probe = mock(PlatformCapabilityProbe.class);
        when(probe.probe()).thenReturn(
                new PlatformCapabilityProbe.Result(argocd, velero, buildNode, warnings));
        return probe;
    }

    // ── runtime probes + images reflected ────────────────────────────────────────────────────

    @Test
    void allInfraPresent_reportsTrue_noWarnings() {
        var c = controller(probeWith(true, true, true, List.of()), isoWith(true),
                false, false, false, false, false);
        StepVerifier.create(c.build())
                .assertNext(caps -> {
                    assertThat(caps.argocdPresent()).isTrue();
                    assertThat(caps.veleroPresent()).isTrue();
                    assertThat(caps.buildNodePresent()).isTrue();
                    assertThat(caps.imagesGenerated()).isTrue();
                    assertThat(caps.warnings()).isEmpty();
                })
                .verifyComplete();
    }

    @Test
    void infraAbsent_reportsFalse_andCarriesProbeWarnings() {
        var c = controller(probeWith(false, false, false,
                        List.of("ArgoCD presence could not be detected")),
                isoWith(false), false, false, false, false, false);
        StepVerifier.create(c.build())
                .assertNext(caps -> {
                    assertThat(caps.argocdPresent()).isFalse();
                    assertThat(caps.veleroPresent()).isFalse();
                    assertThat(caps.buildNodePresent()).isFalse();
                    assertThat(caps.imagesGenerated()).isFalse();
                    assertThat(caps.warnings()).contains("ArgoCD presence could not be detected");
                })
                .verifyComplete();
    }

    // ── images-table fail-safe (DB error -> false + warning, never an error signal) ──────────

    @Test
    void imagesTableError_failsSafe_falseWithWarning_noErrorSignal() {
        IsoRepository iso = mock(IsoRepository.class);
        when(iso.list()).thenReturn(Flux.error(new RuntimeException("db down")));
        var c = controller(probeWith(true, true, true, List.of()), iso,
                false, false, false, false, false);
        StepVerifier.create(c.build())
                .assertNext(caps -> {
                    assertThat(caps.imagesGenerated()).isFalse();
                    assertThat(caps.warnings()).anyMatch(w -> w.contains("images table"));
                })
                .verifyComplete(); // completes normally — NEVER errors out to a 500.
    }

    // ── config flags reflected ───────────────────────────────────────────────────────────────

    @Test
    void configFlags_allOn_reflected() {
        var c = controller(probeWith(false, false, false, List.of()), isoWith(false),
                true, true, true, true, true);
        StepVerifier.create(c.build())
                .assertNext(caps -> {
                    assertThat(caps.anubisEnabled()).isTrue();
                    assertThat(caps.forumEnabled()).isTrue();
                    assertThat(caps.testLaunchEnabled()).isTrue();
                    assertThat(caps.casdoorAdminEnabled()).isTrue();
                    assertThat(caps.homeserverAdminEnabled()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void configFlags_allOff_reflected() {
        var c = controller(probeWith(false, false, false, List.of()), isoWith(false),
                false, false, false, false, false);
        StepVerifier.create(c.build())
                .assertNext(caps -> {
                    assertThat(caps.anubisEnabled()).isFalse();
                    assertThat(caps.forumEnabled()).isFalse();
                    assertThat(caps.testLaunchEnabled()).isFalse();
                    assertThat(caps.casdoorAdminEnabled()).isFalse();
                    assertThat(caps.homeserverAdminEnabled()).isFalse();
                })
                .verifyComplete();
    }
}
