package systems.hugmesh.adminbff.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The UNARMED half of the {@code /bff/internal/**} contract: with no
 * {@code app.internal.token} configured (the dev/test/CI + local-compose default —
 * {@code tests/stack/compose.local.yaml} runs admin-bff with {@code INTERNAL_TOKEN} unset and
 * profiles {@code casdoor,dev}) the subtree behaves EXACTLY as it did under the historic
 * {@code permitAll()}, so no local run, mock stack or existing slice test changes behaviour.
 *
 * <p>This mirrors auth-core's {@code InternalTokenWebFilter} convention ("blank ⇒ no-op") on
 * purpose, and is safe ONLY because a production instance can never be in this state:
 * {@link InternalSurfaceTokenBootGuard} ({@code @Profile("!dev & !test")}) aborts context
 * refresh when the credential is blank — pinned by {@link InternalSurfaceTokenBootGuardTest}.
 */
@WebFluxTest(controllers = InternalProbes.class)
@Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class})
class InternalSurfaceUnarmedParityTest {

    @Autowired ApplicationContext context;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    WebTestClient client;

    @BeforeEach
    void setUp() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @Test
    void unarmed_internalPathsStayReachableWithoutAnyCredential() {
        client.post().uri("/bff/internal/sessions").exchange().expectStatus().isOk();
        client.get().uri("/bff/internal/session/introspect").exchange().expectStatus().isOk();
        client.post().uri("/bff/internal/device-enrollment/self-report")
                .exchange().expectStatus().isOk();
    }

    @Test
    void unarmed_stillDoesNotOpenAnythingOutsideTheInternalSubtree() {
        // The unarmed degradation is scoped to /bff/internal/** — the admin surface keeps its
        // ROLE_ADMIN wall even in a token-less dev run.
        client.get().uri("/bff/admin/allowlist").exchange().expectStatus().isUnauthorized();
    }
}
