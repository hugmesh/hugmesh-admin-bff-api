package net.hugmesh.adminbff;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.profile.ProfileForwarder;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.MfaChallengeService;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import java.util.List;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Shared mocks for the two {@code @WebFluxTest} slices that pin the legacy-path kill switch
 * (hugmesh-admin-bff-api#86) through the REAL {@link AuthController}, the real security chain and
 * the real {@code application.yml}: {@link AuthControllerLegacyPathsDefaultWebFluxTest} (ships
 * dark) and {@link AuthControllerLegacyPathsSwitchedOffWebFluxTest}. The two cannot be one class
 * because the posture is a property of the whole context.
 */
abstract class LegacyPathsSliceSupport {

    /** The five paths issue #2's audit named, as {@code {method, uri}}. */
    static final List<String[]> AUDITED_FIVE = List.of(
            new String[] {"POST", "/bff/register/google"},
            new String[] {"POST", "/bff/register/discord"},
            new String[] {"GET", "/bff/me/namespaces"},
            new String[] {"POST", "/bff/provision/matrix"},
            new String[] {"POST", "/bff/provision/mastodon"});

    @MockitoBean AccountStore store;
    @MockitoBean AccountLocalpartService localparts;
    @MockitoBean ServiceTokenBroker broker;
    @MockitoBean UsageService usage;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean ProfileForwarder profiles;
    @MockitoBean GatewayRevocationClient revocations;
    @MockitoBean MfaChallengeService mfaChallenge;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @Autowired ApplicationContext context;

    @TestConfiguration
    static class Cfg {
        @Bean
        SessionCookieService sessionCookieService() {
            return new SessionCookieService(false, true, null);
        }
    }

    WebTestClient web() {
        return WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }
}
