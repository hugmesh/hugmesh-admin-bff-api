package systems.hugmesh.adminbff.appeal;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.adminbff.config.SecurityConfig;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for {@link AppealContactController}:
 *
 * <ul>
 *   <li>{@code GET /bff/public/appeal-contact} is {@code permitAll} — anonymous callers
 *       (banned / logged-out principals who cannot obtain a JWT) reach it without any
 *       token (P1-1).</li>
 *   <li>Authenticated callers with {@code ROLE_USER} also receive 200 (P1-2 — the endpoint
 *       is public, not restricted, so having a valid token must not break anything).</li>
 *   <li>When {@code app.appeal.contact-email} is NOT configured the controller falls back to
 *       the hard-coded default {@code appeals@hugmesh.systems} (P1-3).</li>
 * </ul>
 *
 * <p>No service/repository layer is involved — the controller is a thin config reader — so
 * no additional mocks are required beyond the mandatory {@link ReactiveJwtDecoder} stub that
 * the {@link SecurityConfig} resource-server wiring demands even though this endpoint never
 * validates a JWT.
 */
@WebFluxTest(controllers = AppealContactController.class)
@Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class})
@TestPropertySource(properties = "app.appeal.contact-email=test-appeal@example.com")
class AppealContactControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    /**
     * The resource-server autoconfiguration requires a {@link ReactiveJwtDecoder} bean even
     * when the endpoint under test is completely public. We stub it here so the
     * {@link WebFluxTest} slice starts without needing a real Casdoor / OIDC issuer.
     */
    @MockitoBean
    ReactiveJwtDecoder jwtDecoder;

    // ── P1-1: anonymous caller (no token) → 200 with configured email ──────────────

    /**
     * A banned or logged-out principal arrives with no JWT. The endpoint MUST return 200
     * and the contact email so the UI can render the mailto link.
     */
    @Test
    void anonymous_gets200WithEmail() {
        web.get().uri("/bff/public/appeal-contact")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("test-appeal@example.com");
    }

    /**
     * The response body must be a JSON object with exactly the {@code email} key —
     * no admin identity, no extra fields that could aid phishing or reconnaissance.
     */
    @Test
    void anonymous_responseContainsOnlyEmailKey() {
        web.get().uri("/bff/public/appeal-contact")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("test-appeal@example.com")
                .jsonPath("$.id").doesNotExist()
                .jsonPath("$.admin").doesNotExist()
                .jsonPath("$.username").doesNotExist();
    }

    // ── P1-2: authenticated ROLE_USER → 200 (public endpoint, token must not block) ─

    /**
     * An authenticated user with {@code ROLE_USER} (e.g. a user who was briefly banned
     * and is now appealing) must receive the same 200 response. The endpoint is public,
     * so presenting a valid JWT should never result in a 403.
     */
    @Test
    void authenticatedUser_gets200() {
        web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/public/appeal-contact")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("test-appeal@example.com");
    }

    /**
     * An authenticated admin should also be able to reach the public endpoint — this
     * guards against accidental over-restriction in future security-config changes.
     */
    @Test
    void authenticatedAdmin_gets200() {
        web.mutateWith(mockJwt().authorities(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")))
                .get().uri("/bff/public/appeal-contact")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("test-appeal@example.com");
    }

    // ── P1-3: missing config → hard-coded default is returned ──────────────────────

    /**
     * When {@code app.appeal.contact-email} is absent from the deployment config the
     * controller must fall back to the Spring-EL default
     * {@code appeals@hugmesh.systems} declared in the {@code @Value} annotation.
     * This slice deliberately does NOT set the property so the default activates.
     */
    @WebFluxTest(controllers = AppealContactController.class)
    @Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class})
    static class MissingConfigTest {

        @Autowired
        WebTestClient web;

        @MockitoBean
        ReactiveJwtDecoder jwtDecoder;

        @Test
        void missingConfig_returnsHardCodedDefault() {
            web.get().uri("/bff/public/appeal-contact")
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.email").isEqualTo("appeals@hugmesh.systems");
        }
    }
}
