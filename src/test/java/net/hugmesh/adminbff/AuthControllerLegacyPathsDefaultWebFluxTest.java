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

/**
 * The SHIPS-DARK posture of the legacy-path kill switch, through the real controller, the real
 * security chain and the real {@code application.yml} (so the yml's own defaults are what is
 * under test): with no property set, none of the five audited paths is answered by the switch.
 * An anonymous caller reaches the registration handlers' validation (400-class, never 404) and is
 * stopped by the security floor on the authenticated ones (401), exactly as before the switch
 * existed. See {@link AuthControllerLegacyPathsSwitchedOffWebFluxTest} for the other posture.
 */
@WebFluxTest(controllers = AuthController.class)
@Import({SecurityConfig.class, net.hugmesh.commons.security.DomainRegistry.class,
        net.hugmesh.adminbff.account.RegistrationDomainResolver.class,
        LocalLoginRateLimiter.class, LegacyPathsSliceSupport.Cfg.class})
class AuthControllerLegacyPathsDefaultWebFluxTest extends LegacyPathsSliceSupport {

    @Test
    void theFilterIsWiredAndSwitchesNothingOff() {
        assertThat(context.getBean(LegacyAuthPathsKillSwitchWebFilter.class).switchedOff()).isEmpty();
    }

    @Test
    void theFiveAuditedPathsAreNotAnsweredByTheSwitch() {
        for (String[] p : AUDITED_FIVE) {
            web().method(HttpMethod.valueOf(p[0])).uri(p[1])
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{}")
                    .exchange()
                    .expectStatus().value(status ->
                            assertThat(status).as("%s %s", p[0], p[1]).isNotEqualTo(404))
                    .expectHeader().doesNotExist("X-Bff-Denied");
        }
    }

    @Test
    void theAuthenticatedAuditedPathsStopAtTheSecurityFloorAs401() {
        web().get().uri("/bff/me/namespaces").exchange().expectStatus().isUnauthorized();
        web().post().uri("/bff/provision/matrix").exchange().expectStatus().isUnauthorized();
        web().post().uri("/bff/provision/mastodon").exchange().expectStatus().isUnauthorized();
    }
}
