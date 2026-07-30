package systems.hugmesh.adminbff.desktop;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.desktop.terminal.DeviceTerminalProperties;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * BFF-STEPUP ships-dark structural assertion: with {@code app.device-terminal.enabled=false} (the
 * DEFAULT — no property set here), the mint 503s and NEVER calls the broker, even for an authorized
 * ADMIN — keeping the whole privileged leg dark until launch. Proves the dark default IN CODE (the
 * flag is not set, so the bound {@link DeviceTerminalProperties#isEnabled()} is false).
 */
@WebFluxTest(controllers = DesktopStepUpController.class)
@Import({SecurityConfig.class, DomainRegistry.class, DeviceTerminalProperties.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DesktopStepUpControllerDarkTest {

    private static final String URI = "/bff/admin/desktop/step-up";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean WorkloadStepUpService stepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asAdmin(String subject) {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(subject)).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Test
    void mint_whileDark_is503_andNeverMints() {
        asAdmin("admin-x").post().uri(URI)
                .exchange().expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.error")
                .value(org.hamcrest.Matchers.containsString("ships dark"));
        // authorization (role gate) ran, but the privileged mint did NOT — dark.
        verify(stepUp, never()).mint(any(), any());
    }
}
