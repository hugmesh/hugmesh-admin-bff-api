package net.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.platform.PlatformCapabilityProbe;

import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ServiceCatalogBuilderController#builderStatus()} — the FOUR combinations
 * of {@code enabled} (the {@code app.appstore.builder.enabled} config flag, modelled as the
 * {@link KanikoBuildLauncher} constructor arg being {@code null}/non-null, the SAME
 * {@code @Nullable} seam {@link AddServiceEffector} uses) crossed with {@code buildNodePresent}
 * (the live {@link PlatformCapabilityProbe} result), plus the fail-safe warnings pass-through.
 * Plain Mockito — no Spring context; the SUPERADMIN authz boundary is covered separately by
 * {@link ServiceCatalogBuilderControllerAuthzTest}.
 */
@ExtendWith(MockitoExtension.class)
class ServiceCatalogBuilderControllerTest {

    @Mock KanikoBuildLauncher builder;
    @Mock PlatformCapabilityProbe capabilityProbe;

    @Test
    @SuppressWarnings("unchecked")
    void disabledAndNoBuildNode_reportsBothFalse_thisEnvironmentsTruth() {
        // The default state of THIS (and every un-flipped) environment: no builder bean, no x86
        // build node — honest disclosure, never a faked true.
        when(capabilityProbe.probe()).thenReturn(new PlatformCapabilityProbe.Result(false, false,
                false, List.of("x86 build-node presence could not be detected (Node list failed "
                        + "or was denied); reported absent.")));
        ServiceCatalogBuilderController controller = new ServiceCatalogBuilderController(null, capabilityProbe);

        StepVerifier.create(controller.builderStatus())
                .assertNext(body -> {
                    org.assertj.core.api.Assertions.assertThat(body.get("enabled")).isEqualTo(false);
                    org.assertj.core.api.Assertions.assertThat(body.get("buildNodePresent")).isEqualTo(false);
                    org.assertj.core.api.Assertions.assertThat((List<String>) body.get("warnings"))
                            .hasSize(1);
                })
                .verifyComplete();
    }

    @Test
    void enabledButNoBuildNode_stillReportsBuildNodeAbsent() {
        // Flag flipped true, but the cluster genuinely has no labelled x86 node: NECESSARY but
        // not SUFFICIENT — the UI must NOT un-gate DOCKERFILE/ZIP on enabled alone.
        when(capabilityProbe.probe())
                .thenReturn(new PlatformCapabilityProbe.Result(false, false, false, List.of()));
        ServiceCatalogBuilderController controller = new ServiceCatalogBuilderController(builder, capabilityProbe);

        StepVerifier.create(controller.builderStatus())
                .assertNext(body -> {
                    org.assertj.core.api.Assertions.assertThat(body.get("enabled")).isEqualTo(true);
                    org.assertj.core.api.Assertions.assertThat(body.get("buildNodePresent")).isEqualTo(false);
                })
                .verifyComplete();
    }

    @Test
    void enabledAndBuildNodePresent_reportsBothTrue_realBuildPossible() {
        when(capabilityProbe.probe())
                .thenReturn(new PlatformCapabilityProbe.Result(false, false, true, List.of()));
        ServiceCatalogBuilderController controller = new ServiceCatalogBuilderController(builder, capabilityProbe);

        StepVerifier.create(controller.builderStatus())
                .assertNext(body -> {
                    org.assertj.core.api.Assertions.assertThat(body.get("enabled")).isEqualTo(true);
                    org.assertj.core.api.Assertions.assertThat(body.get("buildNodePresent")).isEqualTo(true);
                })
                .verifyComplete();
    }

    @Test
    void buildNodePresentButFlagDisabled_stillReportsDisabled() {
        // A build node happens to exist but the operator has not opted the builder in — enabled
        // stays false regardless of what the cluster has.
        when(capabilityProbe.probe())
                .thenReturn(new PlatformCapabilityProbe.Result(false, false, true, List.of()));
        ServiceCatalogBuilderController controller = new ServiceCatalogBuilderController(null, capabilityProbe);

        StepVerifier.create(controller.builderStatus())
                .assertNext(body -> {
                    org.assertj.core.api.Assertions.assertThat(body.get("enabled")).isEqualTo(false);
                    org.assertj.core.api.Assertions.assertThat(body.get("buildNodePresent")).isEqualTo(true);
                })
                .verifyComplete();
    }

    @Test
    void warningsPassThroughVerbatim() {
        List<String> warnings = List.of("Kubernetes client unavailable; ArgoCD / Velero / "
                + "build-node presence could not be detected and are reported absent.");
        when(capabilityProbe.probe())
                .thenReturn(new PlatformCapabilityProbe.Result(false, false, false, warnings));
        ServiceCatalogBuilderController controller = new ServiceCatalogBuilderController(null, capabilityProbe);

        StepVerifier.create(controller.builderStatus())
                .assertNext(body -> org.assertj.core.api.Assertions
                        .assertThat((List<?>) body.get("warnings")).isEqualTo(warnings))
                .verifyComplete();
    }
}
