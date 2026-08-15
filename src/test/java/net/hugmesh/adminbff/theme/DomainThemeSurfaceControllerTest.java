package net.hugmesh.adminbff.theme;

import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The theme resolve endpoint has to work with NO token at all.
 *
 * <p>This is the one property of the whole feature that cannot be checked by looking at
 * the admin UI: the login page is the first surface an anonymous visitor sees, and if
 * this endpoint required authentication it would 401 exactly where the theme is most
 * visible — while every signed-in admin's own testing looked fine. The permitAll rule for
 * {@code /bff/public/**} lives in SecurityConfig, which is imported here so the test
 * exercises the real chain rather than a permissive stand-in.
 */
@WebFluxTest(controllers = DomainThemeSurfaceController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DomainThemeSurfaceControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DomainThemeService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean net.hugmesh.authcore.provision.GatewayRevocationClient revocations;

    private static DomainTheme row(String domain, String preset) {
        return new DomainTheme(domain, preset, "dusk", "sharp", null, null, "admin@x");
    }

    @Test
    void anAnonymousVisitorCanResolveADomainsTheme() {
        when(service.resolve(eq("brandx"))).thenReturn(Mono.just(row("brandx", "nord")));

        web.get().uri("/bff/public/theme?domain=brandx")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.preset").isEqualTo("nord");
    }

    @Test
    void anOmittedDomainResolvesTheMeshDefault() {
        when(service.resolve(any())).thenReturn(Mono.just(row(DomainTheme.MESH_DEFAULT, "dark")));

        web.get().uri("/bff/public/theme")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.preset").isEqualTo("dark");

        verify(service).resolve(null);
    }

    // ── the stylesheet endpoint ─────────────────────────────────────────

    private static DomainTheme rendered(String domain, String css) {
        return new DomainTheme(domain, "nord", "dusk", "sharp", null, null, "admin@x",
                css, "studio");
    }

    @Test
    void theStylesheetIsServedAsCssToAnAnonymousVisitor() {
        when(service.resolve(eq("brandx")))
                .thenReturn(Mono.just(rendered("brandx", ":root:root { --sd-accent: #88c0d0; }")));

        web.get().uri("/bff/public/theme.css?domain=brandx")
                .exchange().expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith("text/css")
                .expectBody(String.class).value(b -> {
                    assertThat(b).contains("--sd-accent");
                    assertThat(b).contains(":root:root");
                });
    }

    @Test
    void aDomainWithNoRenderGetsAnEmptySheetRatherThanA404() {
        // An empty stylesheet is the SHIPPED CHROME: every var(--sd-*, <literal>) falls
        // back. A 404 would put a console error on every page load and change nothing
        // about what renders, and a 500 would be worse.
        when(service.resolve(any())).thenReturn(Mono.just(rendered("brandx", null)));

        web.get().uri("/bff/public/theme.css?domain=brandx")
                .exchange().expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith("text/css")
                .expectBody(String.class).value(b -> assertThat(b).isNullOrEmpty());
    }

    @Test
    void anUnchangedThemeRevalidatesTo304RatherThanResendingTheSheet() {
        // no-cache + ETag: a theme change is visible on the very next load, but an
        // unchanged one costs a conditional request rather than a stylesheet.
        String css = ":root:root { --sd-accent: #88c0d0; }";
        when(service.resolve(any())).thenReturn(Mono.just(rendered("brandx", css)));

        String etag = web.get().uri("/bff/public/theme.css?domain=brandx")
                .exchange().expectStatus().isOk()
                .expectHeader().exists("ETag")
                .returnResult(String.class).getResponseHeaders().getETag();

        when(service.resolve(any())).thenReturn(Mono.just(rendered("brandx", css)));
        web.get().uri("/bff/public/theme.css?domain=brandx").header("If-None-Match", etag)
                .exchange().expectStatus().isNotModified();
    }

    @Test
    void aChangedThemeGetsADifferentEtagSoItCannotBeServedFromCache() {
        when(service.resolve(any()))
                .thenReturn(Mono.just(rendered("brandx", ":root:root { --sd-accent: #88c0d0; }")));
        String etagA = web.get().uri("/bff/public/theme.css?domain=brandx")
                .exchange().expectStatus().isOk()
                .returnResult(String.class).getResponseHeaders().getETag();

        when(service.resolve(any()))
                .thenReturn(Mono.just(rendered("brandx", ":root:root { --sd-accent: #ff0088; }")));
        String etagB = web.get().uri("/bff/public/theme.css?domain=brandx")
                .exchange().expectStatus().isOk()
                .returnResult(String.class).getResponseHeaders().getETag();

        assertThat(etagA).isNotEqualTo(etagB);
    }

    @Test
    void theUpdatedByAuditFieldIsNotExposedOnThePublicSurface() {
        // Who last changed a theme is an admin-side audit fact, not something an
        // anonymous visitor needs in order to render the right colours.
        when(service.resolve(any())).thenReturn(Mono.just(row("brandx", "nord")));

        web.get().uri("/bff/public/theme?domain=brandx")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.updatedBy").doesNotExist()
                .jsonPath("$.updated_by").doesNotExist();
    }
}
