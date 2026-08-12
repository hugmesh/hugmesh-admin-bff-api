package net.hugmesh.adminbff.servicecatalog.scaffold;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.commons.web.ApiException;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The write/read/render surface for {@code service_scaffold} — the Service-Store SCAFFOLD wizard's
 * data layer + on-demand starter-codebase renderer (App-Store). A SUPERADMIN
 * {@link #create}s a scaffold FOR an explicit {@code domain} (the brand is a method argument,
 * NEVER read from a request body) and {@link #archive}s it to a ZIP of the rendered example
 * codebase.
 *
 * <p>DATA/INTENT only — nothing is deployed. {@link #create} validates the archetype against the
 * embedded {@link ScaffoldCatalog} (unknown → 400) and, for a Java-package archetype (spring-bff),
 * rejects a {@code serviceKey} whose slug is not {@code ^[a-z0-9]+$} (it becomes a Java package
 * segment). {@link #archive} renders the vendored skeleton with {@link TokenRenderer}
 * (hard-failing on any unresolved token) on {@code boundedElastic} and CASes the row
 * {@code requested -> archived} (idempotent — a re-download is a pure read).
 */
@Service
public class ScaffoldService {

    private static final Logger log = LoggerFactory.getLogger(ScaffoldService.class);

    /** A Java-package-safe slug: lowercase alphanumeric, NO hyphens (a package segment). */
    private static final Pattern JAVA_PACKAGE_SLUG = Pattern.compile("^[a-z0-9]+$");

    private final ServiceScaffoldRepository repo;
    private final ScaffoldArchiveRenderer renderer;
    private final ScaffoldRenderContext context;

    public ScaffoldService(ServiceScaffoldRepository repo, ScaffoldArchiveRenderer renderer,
                           ScaffoldRenderContext context) {
        this.repo = repo;
        this.renderer = renderer;
        this.context = context;
    }

    /** The embedded scaffold catalog (the archetypes read endpoint payload). */
    public List<ScaffoldArchetype> archetypes() {
        return ScaffoldCatalog.all();
    }

    /**
     * Create a {@code requested} scaffold of {@code serviceKey} in {@code domain} (SUPERADMIN; the
     * domain is the explicit target). Validates the archetype is a catalog member and, for a
     * Java-package archetype, that the derived {@code APP_SLUG} is package-safe. Stamps the
     * superadmin subject.
     */
    public Mono<ServiceScaffold> create(String domain, String serviceKey, String archetype,
                                        String displayName, String mountAt, String requiresRole,
                                        String createdBySubject) {
        if (domain == null || domain.isBlank()) {
            return Mono.error(ApiException.badRequest("domain is required"));
        }
        if (serviceKey == null || serviceKey.isBlank()) {
            return Mono.error(ApiException.badRequest("serviceKey is required"));
        }
        if (!ScaffoldCatalog.contains(archetype)) {
            return Mono.error(ApiException.badRequest("unknown archetype '" + archetype
                    + "' (known: " + ScaffoldCatalog.all().stream().map(ScaffoldArchetype::name).toList() + ")"));
        }
        String slug = ScaffoldRenderContext.appSlug(serviceKey);
        if (ScaffoldCatalog.requiresJavaPackageSafeSlug(archetype)
                && !JAVA_PACKAGE_SLUG.matcher(slug).matches()) {
            return Mono.error(ApiException.badRequest("serviceKey '" + serviceKey + "' yields slug '"
                    + slug + "' which is not a valid Java package segment (required ^[a-z0-9]+$) for the '"
                    + archetype + "' archetype"));
        }
        return repo.insertRequested(domain.trim(), serviceKey.trim(), archetype, displayName, mountAt,
                        requiresRole, createdBySubject)
                .doOnNext(s -> log.info("[scaffold] created {} ({}) in {} by {} (id={})",
                        s.serviceKey(), s.archetype(), s.domain(), createdBySubject, s.id()));
    }

    /**
     * Render the ZIP of the scaffold's starter codebase (SUPERADMIN; the {@code domain} is the
     * explicit target). A 404 when no such scaffold exists; a 400 when it is not in {@code domain}
     * (the superadmin's explicit target, mirroring the provision domain guard). The render runs on
     * {@code boundedElastic} (blocking classpath read + zip); a successful render CASes the row
     * {@code requested -> archived} (best-effort, idempotent) before returning the bytes.
     */
    public Mono<byte[]> archive(String domain, String id) {
        return repo.findById(id)
                .switchIfEmpty(Mono.error(ApiException.notFound("no scaffold '" + id + "'")))
                .flatMap(s -> renderArchive(s, domain));
    }

    private Mono<byte[]> renderArchive(ServiceScaffold s, String domain) {
        if (s.domain() != null && !s.domain().equals(domain)) {
            return Mono.error(ApiException.badRequest(
                    "scaffold '" + s.id() + "' is not in domain '" + domain + "'"));
        }
        Map<String, String> ctx = context.build(s.domain(), s.serviceKey(), s.displayName());
        boolean relocate = ScaffoldCatalog.requiresJavaPackageSafeSlug(s.archetype());
        String appSlug = ScaffoldRenderContext.appSlug(s.serviceKey());
        return Mono.fromCallable(() -> renderer.render(s.archetype(), appSlug, relocate, ctx))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(bytes -> repo.markArchived(s.id())
                        .doOnNext(n -> {
                            if (n == 1L) {
                                log.info("[scaffold] archived id={} ({} bytes)", s.id(), bytes.length);
                            }
                        })
                        .thenReturn(bytes));
    }

    /** Every scaffold for an EXPLICIT {@code domain} (the superadmin per-domain view). */
    public Flux<ServiceScaffold> listForDomain(String domain) {
        if (domain == null || domain.isBlank()) {
            return Flux.error(ApiException.badRequest("domain is required"));
        }
        return repo.findByDomain(domain.trim());
    }
}
