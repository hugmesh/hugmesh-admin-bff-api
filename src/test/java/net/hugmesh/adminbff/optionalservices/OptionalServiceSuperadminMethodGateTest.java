package net.hugmesh.adminbff.optionalservices;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The SECOND of the two authorization gates, proven INDEPENDENTLY.
 *
 * <p>{@link OptionalServiceSuperadminControllerTest} imports the real {@code SecurityConfig}, so
 * its 403s are produced by the coarse {@code /bff/superadmin/**} path matcher BEFORE the
 * per-method {@code @PreAuthorize} is ever consulted. That was measured, not assumed: deleting
 * every {@code @PreAuthorize("hasRole('SUPERADMIN')")} from the controller left that suite
 * entirely GREEN. A defence-in-depth annotation nothing can fail is decoration.
 *
 * <p>This slice removes the outer gate — a permit-all chain with
 * {@code @EnableReactiveMethodSecurity} — so the ONLY thing standing between a caller and the
 * handler is the method annotation. ROLE_ADMIN / ROLE_MOD / ROLE_USER must still be refused, and
 * must still never reach the cluster seam.
 */
@WebFluxTest(controllers = OptionalServiceSuperadminController.class)
@Import({OptionalServiceSuperadminMethodGateTest.MethodSecurityOnlyConfig.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class,
        OptionalServiceAdminService.class, OptionalServiceRegistry.class})
class OptionalServiceSuperadminMethodGateTest {

    private static final String PATH = "/bff/superadmin/optional-services";
    private static final String ON = "{\"enabled\":true}";

    /** Authentication without authorization: every path permitted, method security ON. */
    @EnableWebFluxSecurity
    @EnableReactiveMethodSecurity
    static class MethodSecurityOnlyConfig {
        @Bean
        SecurityWebFilterChain permitEverythingChain(ServerHttpSecurity http) {
            return http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                    .authorizeExchange(ex -> ex.anyExchange().permitAll())
                    .build();
        }
    }

    @Autowired ApplicationContext context;

    @MockitoBean OptionalServiceClient client;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    WebTestClient web;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        when(client.isReal()).thenReturn(true);
        when(client.listDesired()).thenReturn(List.of());
    }

    private WebTestClient as(String... roles) {
        SimpleGrantedAuthority[] authorities = new SimpleGrantedAuthority[roles.length];
        for (int i = 0; i < roles.length; i++) {
            authorities[i] = new SimpleGrantedAuthority(roles[i]);
        }
        return web.mutateWith(mockJwt().jwt(j -> j.subject("s-1")).authorities(authorities));
    }

    @Test
    void withNoPathGate_theMethodAnnotationStillAdmitsOnlySuperadmin() {
        as("ROLE_USER", "ROLE_SUPERADMIN").get().uri(PATH).exchange().expectStatus().isOk();
    }

    @Test
    void withNoPathGate_theMethodAnnotationStillRefusesAdminModUser_onTheRead() {
        as("ROLE_USER", "ROLE_ADMIN").get().uri(PATH).exchange().expectStatus().isForbidden();
        as("ROLE_USER", "ROLE_MOD").get().uri(PATH).exchange().expectStatus().isForbidden();
        as("ROLE_USER").get().uri(PATH).exchange().expectStatus().isForbidden();
        verify(client, never()).listDesired();
    }

    @Test
    void withNoPathGate_theMethodAnnotationStillRefusesAdminModUser_onTheWrite() {
        for (String role : List.of("ROLE_ADMIN", "ROLE_MOD", "ROLE_USER")) {
            as("ROLE_USER", role).put().uri(PATH + "/akkoma")
                    .contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                    .exchange().expectStatus().isForbidden();
        }
        verify(client, never()).setEnabled(anyString(), anyBoolean(), any(), any());
    }
}
