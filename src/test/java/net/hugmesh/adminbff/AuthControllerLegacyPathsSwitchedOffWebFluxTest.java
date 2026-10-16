package net.hugmesh.adminbff;

import org.junit.jupiter.api.Test;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import net.hugmesh.adminbff.config.LegacyAuthPathsKillSwitchWebFilter;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.locallogin.LocalLoginRateLimiter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * The SWITCHED-OFF posture through the real controller and security chain: with
 * {@code app.auth.legacy-paths.enabled=false} every one of the five audited paths answers 404 with
 * the denial header, even to an AUTHENTICATED caller (who would otherwise reach the handler), and
 * no collaborator of the controller is touched. The default posture is
 * {@link AuthControllerLegacyPathsDefaultWebFluxTest}.
 */
@WebFluxTest(controllers = AuthController.class,
        properties = LegacyAuthPathsKillSwitchWebFilter.ENABLED_PROPERTY + "=false")
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class,
        net.hugmesh.adminbff.account.RegistrationDomainResolver.class,
        LocalLoginRateLimiter.class, LegacyPathsSliceSupport.Cfg.class})
class AuthControllerLegacyPathsSwitchedOffWebFluxTest extends LegacyPathsSliceSupport {

    @Test
    void theFilterIsWiredAndSwitchesTheWholeSurfaceOff() {
        assertThat(context.getBean(LegacyAuthPathsKillSwitchWebFilter.class).switchedOff())
                .isEqualTo(LegacyAuthPathsKillSwitchWebFilter.LEGACY_PATHS);
    }

    @Test
    void theFiveAuditedPathsAnswer404WithTheDenialHeader_toAnAuthenticatedCallerToo() {
        for (String[] p : AUDITED_FIVE) {
            web().mutateWith(mockJwt()).method(HttpMethod.valueOf(p[0])).uri(p[1])
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{\"email\":\"alice@hugmesh.net\",\"provider\":\"google\"}")
                    .exchange()
                    .expectStatus().isNotFound()
                    .expectHeader().valueEquals("X-Bff-Denied", "legacy-path-disabled")
                    .expectBody().isEmpty();
        }
        verifyNoInteractions(store, localparts, broker, usage, profiles, revocations, mfaChallenge);
    }

    @Test
    void anAnonymousCallerGets404NotTheSecurityFloors401() {
        web().get().uri("/bff/me/namespaces").exchange().expectStatus().isNotFound();
        web().post().uri("/bff/provision/matrix").exchange().expectStatus().isNotFound();
    }
}
