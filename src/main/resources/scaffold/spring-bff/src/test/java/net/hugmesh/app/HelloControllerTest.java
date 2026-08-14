package net.hugmesh.{{APP_SLUG}};

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Boots the FULL application context (security chain included) and drives it
 * through a context-bound {@link WebTestClient}. Three honest assertions:
 * the health probe is genuinely public, the API surface genuinely requires a
 * JWT (the DENY leg is asserted, not assumed), and the hello payload carries
 * the EXACT service identity + message the controller promises.
 */
@SpringBootTest
class HelloControllerTest {

    @Autowired
    private ApplicationContext context;

    private WebTestClient client;

    // Spring Security 7: the mockJwt()/mock* reactive mutators only inject the
    // SecurityContext when the springSecurity() configurer's MutatorFilter is in
    // the chain, so build the client from the ApplicationContext with
    // .apply(springSecurity()) (fleet convention — see user-bff-api's gate tests).
    @BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @Test
    void healthIsPublicAndUp() {
        client.get().uri("/actuator/health")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("UP");
    }

    @Test
    void helloWithoutTokenIsDenied() {
        client.get().uri("/api/{{APP_SLUG}}/hello")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void helloWithJwtReturnsServiceAndMessage() {
        client.mutateWith(mockJwt())
                .get().uri("/api/{{APP_SLUG}}/hello")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.service").isEqualTo("{{APP_SLUG}}-bff")
                .jsonPath("$.message").isEqualTo("Hello from {{APP_SLUG}}-bff");
    }
}
