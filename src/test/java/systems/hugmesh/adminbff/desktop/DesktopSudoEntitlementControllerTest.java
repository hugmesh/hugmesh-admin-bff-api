package systems.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * The internal sudo-ENTITLEMENT endpoint ({@code /bff/internal/desktop/sudo/entitlement}) —
 * gated by the prefix's {@code ROLE_SERVICE} floor + in-cluster mTLS (UNARMED here). An
 * active grant -> {@code allowed:true}; an absent/revoked grant -> {@code allowed:false}
 * (DEFAULT NONE, fail-closed). No JWT is required here (mirrors the device self-report
 * internal surface).
 */
@WebFluxTest(controllers = DesktopSudoEntitlementController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DesktopSudoEntitlementControllerTest {

    @Autowired WebTestClient web;

    @MockitoBean DesktopSudoGrantService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @Test
    void entitlement_activeGrant_allowedTrue() {
        when(service.entitlement(eq("alice"), eq("dev-1"))).thenReturn(Mono.just(
                new DesktopSudoGrant("g1", "alice", "dev-1", DesktopSudoGrant.STATE_ACTIVE,
                        "root", Instant.now(), null, null, "brandx", DesktopSudoGrant.PROP_PENDING, 1L)));
        web.get().uri("/bff/internal/desktop/sudo/entitlement?subject=alice&deviceId=dev-1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.allowed").isEqualTo(true)
                .jsonPath("$.grantId").isEqualTo("g1");
    }

    @Test
    void entitlement_noGrant_allowedFalse_defaultNone() {
        when(service.entitlement(eq("bob"), eq("dev-1"))).thenReturn(Mono.empty());
        web.get().uri("/bff/internal/desktop/sudo/entitlement?subject=bob&deviceId=dev-1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.allowed").isEqualTo(false);
    }

    @Test
    void entitlement_missingParams_isBadRequest() {
        web.get().uri("/bff/internal/desktop/sudo/entitlement?subject=alice")
                .exchange().expectStatus().isBadRequest();
    }
}
