package net.hugmesh.adminbff.platform;

import io.swagger.v3.oas.annotations.Operation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.iso.IsoRepository;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * ADMIN/SUPERADMIN-only BFF surface that reports which FOUNDATIONAL-INFRA capabilities are
 * present on THIS deployment, so the admin UI can degrade its infra-dependent consoles
 * gracefully (show a "not possible without that" notice + suppress the actions) instead of
 * erroring when the infra is absent.
 *
 * <p>{@code GET /bff/admin/platform-capabilities} returns:
 * <pre>{@code
 * {
 *   "argocdPresent":        bool,   // runtime probe (k8s, read-only, fail-safe)
 *   "veleroPresent":        bool,   // runtime probe (k8s, read-only, fail-safe)
 *   "buildNodePresent":     bool,   // runtime probe (k8s, read-only, fail-safe)
 *   "imagesGenerated":      bool,   // runtime probe (images table count > 0, fail-safe)
 *   "anubisEnabled":        bool,   // config flag (app.anubis.enabled)
 *   "forumEnabled":         bool,   // config flag (external.forum.enabled)
 *   "testLaunchEnabled":    bool,   // config flag (testreports.launch.enabled)
 *   "casdoorAdminEnabled":  bool,   // config flag (casdoor.admin.enabled)
 *   "homeserverAdminEnabled": bool, // config flag (homeserver.admin.enabled)
 *   "warnings": [ ... ]             // human-readable notes on anything not detectable
 * }
 * }</pre>
 *
 * <p><b>Coarse-gated</b> by {@code /bff/admin/**} (ADMIN+SUPERADMIN) in {@code SecurityConfig},
 * with the per-method {@code @PreAuthorize} below as defence-in-depth — a MOD/USER is 403, anon
 * is 401, ADMIN/SUPERADMIN 200.
 *
 * <p><b>Read-only + fail-safe.</b> The runtime probes NEVER mutate and NEVER 500: a k8s error /
 * no-access / unreachable DB yields the capability {@code false} plus a {@code warnings} entry
 * (see {@link PlatformCapabilityProbe} and {@link IsoRepository}). The result is cached ~45s so
 * repeated UI polls do not hammer the API server / DB.
 */
@RestController
@RequestMapping("/bff/admin/platform-capabilities")
public class PlatformCapabilitiesController {

    private static final Logger log = LoggerFactory.getLogger(PlatformCapabilitiesController.class);

    /** Probe-result cache window — between the 30-60s the design asks for. */
    static final Duration CACHE_TTL = Duration.ofSeconds(45);

    private final PlatformCapabilityProbe probe;
    private final IsoRepository isoRepository;

    // ── config flags, mirroring the .enabled switches already in application.yml ─────────
    @Value("${app.anubis.enabled:false}")
    private boolean anubisEnabled;
    @Value("${external.forum.enabled:false}")
    private boolean forumEnabled;
    @Value("${testreports.launch.enabled:false}")
    private boolean testLaunchEnabled;
    @Value("${casdoor.admin.enabled:false}")
    private boolean casdoorAdminEnabled;
    @Value("${homeserver.admin.enabled:false}")
    private boolean homeserverAdminEnabled;

    public PlatformCapabilitiesController(PlatformCapabilityProbe probe, IsoRepository isoRepository) {
        this.probe = probe;
        this.isoRepository = isoRepository;
    }

    /**
     * The TTL-cached pipeline holder: an {@code (expiry, Mono)} pair behind an atomic reference. On
     * each request {@link #capabilities()} reuses the held {@code cache(TTL)} Mono while it is still
     * within the window, and rebuilds a fresh one past it — so the UI's repeated polling does not
     * re-probe the API server / DB on every request, yet a probe failure self-heals after ~45s
     * (a permanently-memoised Mono would pin a transient false reading forever).
     */
    private final java.util.concurrent.atomic.AtomicReference<CacheEntry> cache =
            new java.util.concurrent.atomic.AtomicReference<>();

    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Capabilities", operationId = "platformCapabilitiesCapabilities")
    @GetMapping
    public Mono<PlatformCapabilities> capabilities() {
        return Mono.defer(this::cached);
    }

    /** Returns the live (or freshly-rebuilt) cached pipeline. */
    private Mono<PlatformCapabilities> cached() {
        CacheEntry current = cache.get();
        java.time.Instant now = java.time.Instant.now();
        if (current != null && now.isBefore(current.expiry())) {
            return current.value();
        }
        CacheEntry rebuilt = new CacheEntry(now.plus(CACHE_TTL), build());
        cache.set(rebuilt);
        return rebuilt.value();
    }

    /**
     * Builds one capability envelope. The k8s probe is blocking (fabric8 LISTs) so it is scheduled
     * on boundedElastic; the images-table check is reactive. Both fail SAFE — the probe never
     * throws, and an images-table read error is mapped to {@code imagesGenerated=false} + warning,
     * NEVER an error signal. {@code cache()} memoises the in-flight result so concurrent pollers in
     * the same window share the single probe. Package-private so a unit test can drive it directly.
     */
    Mono<PlatformCapabilities> build() {
        return Mono.zip(probeRuntime(), imagesGenerated())
                .map(t -> assemble(t.getT1(), t.getT2().present(), t.getT2().warning()))
                .cache();
    }

    private Mono<PlatformCapabilityProbe.Result> probeRuntime() {
        return Mono.fromCallable(probe::probe).subscribeOn(Schedulers.boundedElastic());
    }

    /** images-table presence (count>0), read-only + fail-safe: a DB error -> absent + warning. */
    private Mono<ImagesProbe> imagesGenerated() {
        return isoRepository.list().hasElements()
                .map(present -> new ImagesProbe(present, null))
                .onErrorResume(e -> {
                    log.warn("[platform-capabilities] images-table read failed: {}", e.toString());
                    return Mono.just(new ImagesProbe(false,
                            "Generated-images presence could not be read from the images table "
                            + "(database unreachable); reported absent."));
                });
    }

    private PlatformCapabilities assemble(PlatformCapabilityProbe.Result runtime,
                                          boolean imagesGenerated, String imagesWarning) {
        List<String> warnings = new ArrayList<>(runtime.warnings());
        if (imagesWarning != null) {
            warnings.add(imagesWarning);
        }
        return new PlatformCapabilities(
                runtime.argocdPresent(),
                runtime.veleroPresent(),
                runtime.buildNodePresent(),
                imagesGenerated,
                anubisEnabled,
                forumEnabled,
                testLaunchEnabled,
                casdoorAdminEnabled,
                homeserverAdminEnabled,
                warnings);
    }

    /** Small carrier so the images probe can return both presence and an optional warning. */
    private record ImagesProbe(boolean present, String warning) {
    }

    /** The TTL-cache holder: a memoised pipeline valid until {@code expiry}. */
    private record CacheEntry(java.time.Instant expiry, Mono<PlatformCapabilities> value) {
    }
}
