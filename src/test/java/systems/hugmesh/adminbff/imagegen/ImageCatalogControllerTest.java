package systems.hugmesh.adminbff.imagegen;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the image + package/service catalog serve: ADMIN/SUPERADMIN gating
 * (@PreAuthorize via SecurityConfig → non-admin 403 / unauthenticated 401) and the VERBATIM
 * pass-through shape of the two vendored generator trees. The provider reads the real
 * classpath {@code catalog/*.json} (the vendored copy), so this slice also proves the resources
 * are present + parseable on the runtime classpath. Drift vs the generator source is asserted
 * separately in {@link ImageCatalogDriftTest}.
 */
@WebFluxTest(controllers = ImageCatalogController.class)
@Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class, ImageCatalogProvider.class})
class ImageCatalogControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    // ── admin serve: verbatim pass-through of both trees ─────────────────────────────
    @Test
    void catalog_admin_servesBothTreesVerbatim() {
        asAdmin().get().uri("/bff/admin/image-builds/catalog")
                .exchange().expectStatus().isOk()
                .expectBody()
                // image-catalog.json — nested inline as JSON (not an escaped string)
                .jsonPath("$.images.platform_labels.x86").isEqualTo("x86_64 host")
                .jsonPath("$.images.role_class.desktop").value(
                        org.hamcrest.Matchers.hasItem("laptop"))
                .jsonPath("$.images.role_class.node").value(
                        org.hamcrest.Matchers.hasItem("pki"))
                .jsonPath("$.images.roles.cloud[0].role").isEqualTo("laptop")
                .jsonPath("$.images.roles.cloud[0].image_class").isEqualTo("desktop")
                // packages-catalog.json — adhoc_adds + per-platform sections
                .jsonPath("$.packages.adhoc_adds.tor.atoms[0]").isEqualTo("net-vpn/tor")
                .jsonPath("$.packages.adhoc_adds.tor.label").isEqualTo("Tor onion service (net-vpn/tor)")
                .jsonPath("$.packages.platforms.frite.packages.gate").isEqualTo("base");
    }

    @Test
    void catalog_superadmin_alsoServes() {
        asSuperadmin().get().uri("/bff/admin/image-builds/catalog")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.images.platform_labels.x86").isEqualTo("x86_64 host");
    }

    // ── the /catalog literal out-specifies /{id} so it never routes to build-detail ──
    @Test
    void catalog_pathDoesNotCollideWithBuildDetailTemplate() {
        // A 200 with the catalog shape (not a build row / 404) proves PathPattern specificity
        // routes /catalog to this controller, not ImageBuildController's /{id} (id="catalog").
        asAdmin().get().uri("/bff/admin/image-builds/catalog")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.packages").exists().jsonPath("$.images").exists();
    }

    // ── role floor: same ADMIN/SUPERADMIN gate as the rest of the console ────────────
    @Test
    void catalog_nonAdmin_403() {
        asUser().get().uri("/bff/admin/image-builds/catalog").exchange().expectStatus().isForbidden();
    }

    @Test
    void catalog_unauthenticated_401() {
        web.get().uri("/bff/admin/image-builds/catalog").exchange().expectStatus().isUnauthorized();
    }
}
