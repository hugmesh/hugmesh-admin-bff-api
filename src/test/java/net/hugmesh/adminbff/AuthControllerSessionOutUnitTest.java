package net.hugmesh.adminbff;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.account.RegistrationDomainResolver;
import net.hugmesh.adminbff.locallogin.LocalLoginRateLimiter;
import net.hugmesh.adminbff.profile.ProfileForwarder;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.MfaChallengeService;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Isolates {@code AuthController.sessionOut}'s OWN cookie-reading logic from
 * {@link SessionCookieWebFilter}'s cookie-&gt;header bridge, WITHOUT a Spring context of any
 * kind — no {@code @WebFluxTest}, no {@code @Import}, no {@code WebTestClient}.
 *
 * <p><b>Why the Spring-slice route does not work here (land-lane re-review,
 * admin-bff-api#102).</b> An earlier version of this class tried the obvious approach — a
 * {@code @WebFluxTest(controllers = AuthController.class)} slice that deliberately omits
 * {@code @Import(SessionCookieWebFilter.class)}, on the assumption (stated as fact in
 * {@link AuthControllerSessionCookieTest}'s class javadoc) that "the {@code @WebFluxTest} slice
 * does not auto-register it". That assumption is FALSE for this app: {@code @WebFluxTest}
 * detects {@code AdminBffApplication} as the nearest {@code @SpringBootConfiguration} and
 * inherits ITS {@code scanBasePackages = {"net.hugmesh.adminbff", "net.hugmesh.authcore"}} —
 * and Spring Boot's {@code WebFluxTypeExcludeFilter} auto-includes {@code WebFilter} beans found
 * by that scan. So {@code SessionCookieWebFilter} (a plain {@code @Component} in
 * {@code net.hugmesh.authcore.config}) gets auto-detected and wired into EVERY
 * {@code @WebFluxTest(controllers = AuthController.class)} slice in this module regardless of
 * any {@code @Import} list — confirmed empirically: a cookie-only request still arrived at the
 * controller with a synthesised {@code Authorization} header even with no explicit import.
 * There is no {@code @WebFluxTest} configuration in THIS app that excludes it short of an
 * explicit {@code @ComponentScan.Filter} exclusion, which is more fragile than simply not using
 * Spring here at all.
 *
 * <p>This class instantiates {@code AuthController} directly with Mockito mocks — no Spring
 * context, no component scanning, so nothing can auto-wire a filter that was not asked for.
 * {@code sessionOut} is called as a plain Java method with a {@code null} {@code header} and a
 * populated {@code cookie}, mirroring exactly what a cookie-only browser request looks like
 * ONCE (and only once) the request has left the WebFilter chain — i.e. the controller's own
 * argument resolution, which in the real app also runs after the (unconditional) bridge, but
 * here runs with nothing having touched the header first.
 */
class AuthControllerSessionOutUnitTest {

    private final AccountStore store = mock(AccountStore.class);
    private final ServiceTokenBroker broker = mock(ServiceTokenBroker.class);
    private final UsageService usage = mock(UsageService.class);
    private final SuspensionService suspensions = mock(SuspensionService.class);
    private final ProfileForwarder profiles = mock(ProfileForwarder.class);
    private final SessionCookieService cookies = mock(SessionCookieService.class);
    private final GatewayRevocationClient revocations = mock(GatewayRevocationClient.class);
    private final MfaChallengeService mfaChallenge = mock(MfaChallengeService.class);
    private final LocalLoginRateLimiter rateLimiter = mock(LocalLoginRateLimiter.class);
    private final AccountLocalpartService localparts = mock(AccountLocalpartService.class);
    private final RegistrationDomainResolver registrationDomains = mock(RegistrationDomainResolver.class);
    private final ServerWebExchange exchange = mock(ServerWebExchange.class);

    private AuthController newController() {
        AuthController c = new AuthController(store, broker, usage, suspensions, profiles, cookies,
                revocations, mfaChallenge, /* localSecretVerifier */ null, rateLimiter, localparts,
                registrationDomains);
        // Cookie mode dark (matches AuthControllerSessionCookieTest): no Set-Cookie side effect
        // to model, so sessionOut never touches exchange.getResponse().
        when(cookies.expire()).thenReturn(null);
        when(store.deleteSession(anyString())).thenReturn(Mono.just("google:isolated@x.com"));
        when(localparts.localpartOf(anyString())).thenReturn(Mono.empty());
        when(revocations.revokeCoarse(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(Mono.empty());
        when(mfaChallenge.clearProperty(anyString())).thenReturn(Mono.empty());
        return c;
    }

    /**
     * DECISIVE for admin-bff-api#102, with NO Spring context of any kind: a cookie-only call
     * (cookie set, header {@code null}) must delete the session row via the STORE, i.e. resolve
     * the token from the cookie. This is what the current {@code bffTokenFrom(cookie, header)}
     * does. Flip that back to the pre-#102 {@code bffTokenFrom(null, header)} and this test goes
     * RED ({@code store.deleteSession} is never invoked) — verified by hand for this land, see
     * the PR body for the exact revert/RED/restore/GREEN cycle.
     */
    @Test
    void sessionOut_cookieOnly_noHeader_resolvesTokenFromCookie_callsDeleteSession() {
        AuthController controller = newController();
        String token = "bff_isolatedUnitTestToken";

        controller.sessionOut(null, token, /* header */ null, exchange).block();

        verify(store).deleteSession(token);
    }

    /** Companion control: with NEITHER carrier present, sessionOut must NOT call the store at
     *  all — proves the assertion above is actually exercising token resolution, not just
     *  "any call always deletes". */
    @Test
    void sessionOut_noCarrierAtAll_neverCallsDeleteSession() {
        AuthController controller = newController();

        Object result = controller.sessionOut(null, null, null, exchange).block();

        verify(store, never()).deleteSession(anyString());
        assertThat(result).isNotNull(); // still {"loggedOut": true} -- the idempotent shape.
    }

    /** Companion control: the legacy Bearer-header carrier (no cookie) still resolves, exactly
     *  as it did before #102 -- this PR only ADDS the cookie carrier, it does not remove the
     *  header one. */
    @Test
    void sessionOut_headerOnly_stillResolvesTokenFromHeader() {
        AuthController controller = newController();
        String token = "bff_headerCarrierToken";

        controller.sessionOut(null, null, "Bearer " + token, exchange).block();

        verify(store).deleteSession(token);
    }
}
