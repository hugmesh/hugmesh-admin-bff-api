package net.hugmesh.adminbff.capability;

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
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the SERVICE-to-service capability check
 * ({@code /bff/internal/domain-capabilities/{domain}/{capability}}). The load-bearing
 * security property mirrored from {@code GoLiveInternalControllerTest} /
 * {@code InternalAccountControllerTest}: {@code /bff/internal/**} is reachable WITHOUT a
 * Casdoor JWT — the caller presents {@code X-Internal-Token} against the prefix's
 * {@code ROLE_SERVICE} floor, UNARMED in this slice (dev/test parity). The service is mocked so this test
 * isolates the request/response SHAPE contract user-bff's future claim-path integration
 * will rely on; the two-tier ALLOW/DENY truth table itself is
 * {@link DomainCapabilityServiceTest}.
 */
@WebFluxTest(controllers = DomainCapabilityInternalController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class DomainCapabilityInternalControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DomainCapabilityService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String CAP = DomainCapability.USER_MESH_DEVICES;

    @Test
    void active_internalPath_isReachableWithoutJwt_true() {
        when(service.isActive(eq("brandx"), eq(CAP))).thenReturn(Mono.just(true));
        web.get().uri("/bff/internal/domain-capabilities/brandx/" + CAP)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.active").isEqualTo(true);
    }

    @Test
    void active_falseForAnUngrantedDomain_stillA200_neverAnError() {
        when(service.isActive(eq("brandy"), eq(CAP))).thenReturn(Mono.just(false));
        web.get().uri("/bff/internal/domain-capabilities/brandy/" + CAP)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.active").isEqualTo(false);
    }
}
