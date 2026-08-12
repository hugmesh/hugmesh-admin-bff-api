package net.hugmesh.adminbff.servicecatalog;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.lang.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.platform.PlatformCapabilityProbe;

import java.util.List;
import java.util.Map;

/**
 * Pre-flight CAPABILITY seam for the App-Store superadmin UI's DOCKERFILE/ZIP sources: exposes
 * whether the in-cluster Kaniko builder ({@link KanikoBuildLauncher}) is wired AND whether a real
 * x86/amd64 build node is present, so the UI can un-gate those two sources ONLY when a real build
 * is actually possible instead of the previous hardcoded-always-disabled static gate.
 *
 * <h3>Two independent signals</h3>
 * <ul>
 *   <li>{@code enabled} — the {@code app.appstore.builder.enabled} config flag: whether the
 *       {@link KanikoBuildLauncher} bean exists on THIS deployment. NECESSARY but not SUFFICIENT
 *       for a real build.</li>
 *   <li>{@code buildNodePresent} — a LIVE, read-only, fail-safe k8s probe (the SAME
 *       {@link PlatformCapabilityProbe} the {@code /bff/admin/platform-capabilities} envelope
 *       uses) for at least one Node carrying the x86 build-node label. A k8s error / no-access
 *       yields {@code false} plus a {@code warnings} entry, NEVER an exception or a faked
 *       {@code true} — this environment reports its true state, honestly.</li>
 * </ul>
 * A real build is possible ONLY when BOTH are {@code true}; the UI is expected to require both
 * before presenting DOCKERFILE/ZIP as enabled. The bff's {@link AddServiceEffector} 400-guard
 * remains the AUTHORITATIVE gate regardless of what this pre-flight reports.
 *
 * <h3>Authorization — SUPERADMIN-ONLY (defence-in-depth)</h3>
 * Mounted under {@code /bff/superadmin/**} (coarse gate in
 * {@link net.hugmesh.adminbff.config.SecurityConfig}) and additionally guarded by
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")}. ADMIN / MOD / USER → 403.
 */
@RestController
@RequestMapping("/bff/superadmin/service-store")
public class ServiceCatalogBuilderController {

    /** Present (non-null) only when {@code app.appstore.builder.enabled=true} — the SAME
     *  {@code @Nullable KanikoBuildLauncher} seam {@link AddServiceEffector} is constructed with
     *  (Spring's {@code @ConditionalOnProperty} means no bean exists when disabled). Null-ness IS
     *  the signal; this controller never calls a method on it. */
    @Nullable
    private final KanikoBuildLauncher builder;
    private final PlatformCapabilityProbe capabilityProbe;

    public ServiceCatalogBuilderController(@Nullable KanikoBuildLauncher builder,
                                           PlatformCapabilityProbe capabilityProbe) {
        this.builder = builder;
        this.capabilityProbe = capabilityProbe;
    }

    /**
     * Returns {@code {enabled, buildNodePresent, warnings}}. {@code enabled} is read
     * synchronously (bean presence); {@code buildNodePresent} runs the k8s probe on
     * {@code boundedElastic} (the SAME pattern {@code PlatformCapabilitiesController} uses) so the
     * blocking fabric8 LIST never touches the event loop.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Kaniko builder capability: config flag + live x86 build-node presence.",
               operationId = "serviceCatalogBuilderStatus")
    @GetMapping("/builder")
    public Mono<Map<String, Object>> builderStatus() {
        boolean enabled = builder != null;
        return Mono.fromCallable(capabilityProbe::probe)
                .subscribeOn(Schedulers.boundedElastic())
                .map(result -> Map.<String, Object>of(
                        "enabled", enabled,
                        "buildNodePresent", result.buildNodePresent(),
                        "warnings", result.warnings()))
                .defaultIfEmpty(Map.of(
                        "enabled", enabled,
                        "buildNodePresent", false,
                        "warnings", List.of("build-node presence could not be probed")));
    }
}
