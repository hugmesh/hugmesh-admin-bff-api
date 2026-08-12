package net.hugmesh.adminbff.imagegen;

import io.swagger.v3.oas.annotations.Operation;
import tools.jackson.databind.JsonNode;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * ADMIN/SUPERADMIN read-only serve of the generator's image + package/service catalogs —
 * the single source the image-gen wizard (and the tree-multiselect package modal) read to
 * render the role×platform matrix and the package tree. Pattern = the static, non-secret
 * {@link net.hugmesh.adminbff.golive.GoLiveController#providers() go-live provider
 * catalog} static-serve, but the payload here is the generator's VERBATIM JSON (loaded from
 * the classpath by {@link ImageCatalogProvider}), not a Java-declared record list.
 *
 * <p><b>Defence-in-depth gating.</b> The gateway denies {@code /bff/admin/**} to non-admins,
 * {@code SecurityConfig} re-applies {@code hasAnyRole('ADMIN','SUPERADMIN')} on the path, AND
 * {@code @PreAuthorize} re-checks here. The catalog is PUBLIC, non-secret build metadata (no
 * credentials, no tenant data) — the role floor is the same as the rest of the image-gen
 * console it feeds.
 *
 * <p><b>Verbatim pass-through.</b> The response is {@code {"packages":<packages-catalog.json>,
 * "images":<image-catalog.json>}} — the two generator trees nested inline (they are
 * {@link JsonNode}s, so Jackson serialises them as their own JSON, never as escaped strings).
 * The mount is a sibling of the build endpoints under
 * {@code /bff/admin/image-builds/catalog}; the {@code /catalog} literal segment out-specifies
 * {@link ImageBuildController}'s {@code /{id}} template (PathPattern specificity), so it never
 * collides with a build-detail lookup.
 *
 * <p><b>Deferred/structural.</b> Only the tree + gate LABELS ship here. The gating PREDICATES,
 * the essential-floor, and the live essentials/default_set TIER split live in the generator's
 * {@code package_catalog.tiers()} (python, baked into the image-gen container) — live tier
 * resolution is deferred; the modal greys against the catalog's declared floor if present, else
 * shows all as toggleable.
 */
@RestController
@RequestMapping("/bff/admin/image-builds")
@Validated
public class ImageCatalogController {

    private final ImageCatalogProvider catalog;

    public ImageCatalogController(ImageCatalogProvider catalog) {
        this.catalog = catalog;
    }

    // ── image + package/service catalog (read; static, non-secret) ──────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Catalog", operationId = "imageBuildCatalog")
    @GetMapping("/catalog")
    public Mono<Map<String, JsonNode>> catalog() {
        Map<String, JsonNode> out = new LinkedHashMap<>();
        out.put("packages", catalog.packages());
        out.put("images", catalog.images());
        return Mono.just(out);
    }
}
