package net.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.config.InternalTokenWebFilter;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * End-to-end proof that {@link InternalTokenWebFilter} guards the privilege-bearing internal
 * sudo-ENTITLEMENT read when ARMED ({@code app.internal.token} set): a request without the
 * token is a 401 BEFORE the controller/service is touched, and a request carrying the correct
 * token reaches it. This is the defence-in-depth layer ON TOP of mTLS for the per-(subject,
 * device) sudo-state leak.
 */
@WebFluxTest(controllers = DesktopSudoEntitlementController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class, InternalTokenWebFilter.class})
@TestPropertySource(properties = {
        "app.internal.token=s3cret",
        "app.internal.token-header=X-Internal-Token"
})
class DesktopSudoEntitlementInternalTokenTest {

    @Autowired WebTestClient web;

    @MockitoBean DesktopSudoGrantService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String URI = "/bff/internal/desktop/sudo/entitlement?subject=alice&deviceId=dev-1";

    @Test
    void armed_missingInternalToken_is401_andServiceNeverConsulted() {
        web.get().uri(URI).exchange().expectStatus().isUnauthorized();
        verify(service, never()).entitlement(eq("alice"), eq("dev-1"));
    }

    @Test
    void armed_wrongInternalToken_is401() {
        web.get().uri(URI).header("X-Internal-Token", "WRONG")
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).entitlement(eq("alice"), eq("dev-1"));
    }

    @Test
    void armed_correctInternalToken_reachesController() {
        when(service.entitlement(eq("alice"), eq("dev-1"))).thenReturn(Mono.just(
                new DesktopSudoGrant("g1", "alice", "dev-1", DesktopSudoGrant.STATE_ACTIVE,
                        "root", Instant.now(), null, null, "brandx", DesktopSudoGrant.PROP_PENDING, 1L)));
        web.get().uri(URI).header("X-Internal-Token", "s3cret")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.allowed").isEqualTo(true);
    }
}
