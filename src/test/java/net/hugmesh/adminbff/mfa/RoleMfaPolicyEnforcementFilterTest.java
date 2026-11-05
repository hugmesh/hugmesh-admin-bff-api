package net.hugmesh.adminbff.mfa;

import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.security.Roles;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * {@link RoleMfaPolicyEnforcementFilter} with the flag ON, behind the PRODUCTION
 * {@link SecurityConfig}: the enforcement caller of {@link RoleMfaPolicyService#requirementFor}.
 *
 * <p>The guarded endpoint is the real {@code GET /bff/admin/mfa/role-policy}; the policy service
 * is a mock so each test chooses the answer {@code requirementFor} gives and can prove whether
 * the filter asked at all. The dark-by-default half lives in
 * {@link RoleMfaPolicyEnforcementFilterFlagTest}; the session-stamp grace and method checks
 * (which need the cookie bridge) live in {@link RoleMfaPolicyEnforcementEvidenceBindingTest}.
 * The JWT-carrier grace and method checks are at the end of this class.
 */
@WebFluxTest(controllers = RoleMfaPolicyController.class,
        properties = RoleMfaPolicyEnforcementFilter.FLAG + "=true")
@Import({SecurityConfig.class, ValidationExceptionHandler.class, ApiExceptionHandler.class,
        RoleMfaPolicyEnforcementFilter.class})
class RoleMfaPolicyEnforcementFilterTest {

    static final String BRANDX_ISS = "https://idp.brandx.example";
    static final String UNKNOWN_ISS = "https://idp.nobody.example";
    static final String GUARDED = "/bff/admin/mfa/role-policy";

    /** Required on the platform window with any method: the pre-grace/methods answer. */
    static final MfaRequirement REQUIRED = MfaRequirement.UNKNOWN;

    @TestConfiguration
    static class Registry {
        @Bean
        DomainRegistry domainRegistry() {
            return new DomainRegistry("", BRANDX_ISS + "=brandx");
        }
    }

    @Autowired ApplicationContext context;

    @MockitoBean RoleMfaPolicyService service;
    @MockitoBean MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    WebTestClient web;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        when(mfaStepUp.enabled()).thenReturn(true);
        when(mfaStepUp.freshness()).thenReturn(Duration.ofMinutes(10));
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(service.listEffective(anyString())).thenReturn(Flux.empty());
    }

    private WebTestClient as(String issuer, String... authorities) {
        SimpleGrantedAuthority[] auths = new SimpleGrantedAuthority[authorities.length];
        for (int i = 0; i < authorities.length; i++) auths[i] = new SimpleGrantedAuthority(authorities[i]);
        return web.mutateWith(mockJwt()
                .jwt(j -> j.issuer(issuer).subject("subj"))
                .authorities(auths));
    }

    private WebTestClient admin(String... extra) {
        String[] a = new String[extra.length + 2];
        a[0] = "ROLE_USER";
        a[1] = "ROLE_ADMIN";
        System.arraycopy(extra, 0, a, 2, extra.length);
        return as(BRANDX_ISS, a);
    }

    // ── denial ────────────────────────────────────────────────────────────────────

    @Test
    void requiredRole_withNoMfaEvidence_isDenied403_withSignal_andNeverReachesTheController() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(REQUIRED));

        admin().get().uri(GUARDED).exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(RoleMfaPolicyEnforcementFilter.SIGNAL_HEADER, "true")
                .expectBody().jsonPath("$.error").value(e ->
                        assertThat(e.toString()).contains("multi-factor authentication is required"));

        verify(service, never()).listEffective(anyString());
    }

    @Test
    void requiredRole_withAStaleOrAbsentBffSession_isDenied() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(REQUIRED));

        // a cookie whose stamp is NOT fresh (isFresh -> false), and no session at all
        admin().get().uri(GUARDED).cookie("bff_session", "bff_stale").exchange()
                .expectStatus().isForbidden();
        admin().get().uri(GUARDED).exchange().expectStatus().isForbidden();
        verify(service, never()).listEffective(anyString());
    }

    @Test
    void superadminSurface_isGatedToo() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(REQUIRED));

        as(BRANDX_ISS, "ROLE_USER", "ROLE_SUPERADMIN").get().uri("/bff/superadmin/anything").exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(RoleMfaPolicyEnforcementFilter.SIGNAL_HEADER, "true");
    }

    // ── spelling variants of the gated path: gate on what the router matches ───────────

    /** Every one of these is a spelling of a privileged surface and must be classified gated. */
    static final List<String> GATED_SPELLINGS = List.of(
            "/bff/admin/mfa/role-policy",
            "/bff/%61dmin/mfa/role-policy",
            "/bff/%61%64%6d%69%6e/mfa/role-policy",
            "/bff/admin/mfa/%72ole-policy",
            "/bff/admin%2Fmfa/role-policy",
            "/bff/admin%2fmfa%2frole-policy",
            "/bff/admin%5Cmfa/role-policy",
            "/bff/admin;x=1/mfa/role-policy",
            "/bff/admin/mfa;y=2/role-policy",
            "/bff/admin%3Bx=1/mfa/role-policy",
            "/bff/mfa/../admin/mfa/role-policy",
            "/bff/mfa/%2e%2e/admin/mfa/role-policy",
            "/bff/mfa%2F..%2Fadmin/mfa/role-policy",
            "/bff/./admin/mfa/role-policy",
            "/bff//admin/mfa/role-policy",
            "/bff/%2561dmin/mfa/role-policy",
            "/bff/%252561dmin/mfa/role-policy",
            "/bff/ADMIN/mfa/role-policy",
            "/BFF/Admin/mfa/role-policy",
            "/bff/SuperAdmin/anything",
            "/bff/%73uperadmin/anything",
            "/bff/admin",
            "/bff/admin/",
            "/bff/superadmin",
            "/bff/superadmin/");

    /** Spellings of routes that are NOT privileged surfaces: gating them would break MFA enrolment. */
    static final List<String> UNGATED_SPELLINGS = List.of(
            "/bff/mfa/challenge", "/bff/mfa/challenge/", "/bff/%6dfa/challenge", "/bff/administrator",
            "/bff/%61dministrator", "/bff/me;x=1", "/bff/mfa/admin", "/bff/mfa/../me", "/bff", "/",
            "/bff/internal/session/introspect", "/other/admin/x");

    @Test
    void everySpellingOfAPrivilegedSurface_isClassifiedGated() {
        for (String path : GATED_SPELLINGS) {
            assertThat(RoleMfaPolicyEnforcementFilter.gated(path)).as(path).isTrue();
        }
    }

    @Test
    void routesThatAreNotPrivilegedSurfaces_areNotGated() {
        for (String path : UNGATED_SPELLINGS) {
            assertThat(RoleMfaPolicyEnforcementFilter.gated(path)).as(path).isFalse();
        }
    }

    @Test
    void theDecisionIsMadeOnTheContextRelativePath() {
        var withContext = org.springframework.http.server.RequestPath.parse("/app/bff/%61dmin/x", "/app");
        assertThat(RoleMfaPolicyEnforcementFilter.gated(withContext)).isTrue();
    }

    /** The exploit input: an encoded letter routes to the controller, so it must be refused first. */
    @Test
    void aPercentEncodedLetterInTheSegment_isDenied403_andNeverReachesTheController() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(REQUIRED));

        admin().get().uri(URI.create("/bff/%61dmin/mfa/role-policy")).exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(RoleMfaPolicyEnforcementFilter.SIGNAL_HEADER, "true");
        admin().get().uri(URI.create("/bff/admin/mfa/%72ole-policy")).exchange()
                .expectStatus().isForbidden();

        verify(service, never()).listEffective(anyString());
    }

    @Test
    void noSpellingOfAGatedPath_everReachesTheController_forAPolicyRequiredPrincipalWithoutEvidence() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(REQUIRED));

        for (String path : GATED_SPELLINGS) {
            admin().get().uri(URI.create(path)).exchange()
                    .expectStatus().value(code -> assertThat(code).as(path).isIn(400, 403, 404));
        }

        verify(service, never()).listEffective(anyString());
    }

    @Test
    void aPolicyLookupThatYieldsNothing_failsClosed() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.empty());

        admin().get().uri(GUARDED).exchange().expectStatus().isForbidden();
        verify(service, never()).listEffective(anyString());
    }

    @Test
    void aFreshnessLookupThatYieldsNothing_failsClosed() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(REQUIRED));
        when(mfaStepUp.isFresh("bff_empty")).thenReturn(Mono.empty());

        admin().get().uri(GUARDED).cookie("bff_session", "bff_empty").exchange().expectStatus().isForbidden();
        verify(service, never()).listEffective(anyString());
    }

    // ── allowed ───────────────────────────────────────────────────────────────────

    @Test
    void requiredRole_withTheMfaSatisfiedAuthority_isLetThrough_withoutASessionLookup() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(REQUIRED));

        admin("MFA_SATISFIED").get().uri(GUARDED).exchange().expectStatus().isOk();

        verify(mfaStepUp, never()).isFresh(any());
        verify(service).listEffective("brandx");
    }

    /**
     * A JWT principal plus a freshly stamped {@code bff_session} cookie: the cookie is not the
     * principal's session, so its stamp is not evidence. (Deployed, the session-cookie bridge
     * would have made the cookie the principal; the pass for a fresh session lives in
     * {@link RoleMfaPolicyEnforcementEvidenceBindingTest}, which runs that bridge.)
     */
    @Test
    void requiredRole_withAFreshCookieThatIsNotThePrincipalsSession_isDenied() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(REQUIRED));
        when(mfaStepUp.isFresh("bff_fresh")).thenReturn(Mono.just(true));

        admin().get().uri(GUARDED).cookie("bff_session", "bff_fresh").exchange()
                .expectStatus().isForbidden();

        verify(mfaStepUp, never()).isFresh(any());
        verify(service, never()).listEffective(anyString());
    }

    @Test
    void roleNotRequiringMfa_isLetThrough_withoutAnyFreshnessLookup() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(MfaRequirement.NONE));

        admin().get().uri(GUARDED).exchange().expectStatus().isOk();

        verify(mfaStepUp, never()).isFresh(any());
    }

    // ── what the filter asks ──────────────────────────────────────────────────────

    @Test
    void asksThePolicyWithTheIssuerDomain_andTheRoleAuthorities_butNotTheMfaMarker() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(MfaRequirement.NONE));

        admin("MFA_SATISFIED").get().uri(GUARDED).exchange().expectStatus().isOk();

        ArgumentCaptor<Collection<String>> roles = ArgumentCaptor.captor();
        verify(service).requirementFor(eq("brandx"), roles.capture());
        assertThat(roles.getValue()).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void anUnresolvableIssuer_isAskedAboutUnderTheNoDomainSentinel_neverARequestValue() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(REQUIRED));

        as(UNKNOWN_ISS, "ROLE_USER", "ROLE_ADMIN").get().uri(GUARDED + "?domain=brandx").exchange()
                .expectStatus().isForbidden();

        verify(service).requirementFor(eq(PrincipalDomain.NO_DOMAIN), any());
        verify(service, never()).requirementFor(eq("brandx"), any());
    }

    // ── what must stay reachable ──────────────────────────────────────────────────

    @Test
    void theRoutesThatLetAPrincipalGetMfa_areNeverGated() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(REQUIRED));

        for (String path : List.of("/bff/mfa/challenge", "/bff/session", "/bff/sessionOut", "/bff/me",
                "/bff/login", "/bff/internal/session/introspect")) {
            admin().get().uri(path).exchange()
                    .expectHeader().doesNotExist(RoleMfaPolicyEnforcementFilter.SIGNAL_HEADER);
        }

        verify(service, never()).requirementFor(anyString(), any());
    }

    @Test
    void gatedPrefixes_areExactlyTheTwoPrivilegedSurfaces() {
        assertThat(RoleMfaPolicyEnforcementFilter.GATED_SEGMENTS)
                .containsExactlyInAnyOrder("admin", "superadmin");
        assertThat(RoleMfaPolicyEnforcementFilter.gated("/bff/admin/x")).isTrue();
        assertThat(RoleMfaPolicyEnforcementFilter.gated("/bff/superadmin/x")).isTrue();
        assertThat(RoleMfaPolicyEnforcementFilter.gated("/bff/administrator")).isFalse();
        assertThat(RoleMfaPolicyEnforcementFilter.gated("/bff/mfa/x")).isFalse();
    }

    @Test
    void anonymous_isLeftToTheSecurityChain_andNeverAsksThePolicy() {
        web.get().uri(GUARDED).exchange().expectStatus().isUnauthorized();

        verify(service, never()).requirementFor(anyString(), any());
    }

    @Test
    void whenTheStampingMachineryIsOff_theFilterPassesEverythingThrough() {
        when(mfaStepUp.enabled()).thenReturn(false);
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(REQUIRED));

        admin().get().uri(GUARDED).exchange().expectStatus().isOk();

        verify(service, never()).requirementFor(anyString(), any());
    }

    // ── the JWT carrier: grace re-reads the stamp claim, methods read the amr claim ─────

    /** An admin JWT carrying the authority plus the claims the BFF stamps. */
    private WebTestClient stampedAdmin(long stampedAtMillis, Object amr) {
        return web.mutateWith(mockJwt()
                .jwt(j -> {
                    j.issuer(BRANDX_ISS).subject("subj");
                    j.claim(Roles.MFA_SATISFIED_AT_CLAIM, Long.toString(stampedAtMillis));
                    if (amr != null) {
                        j.claim("amr", amr);
                    }
                })
                .authorities(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN"),
                        new SimpleGrantedAuthority(Roles.MFA_SATISFIED)));
    }

    private static MfaRequirement requirement(long graceSeconds, String... methods) {
        return new MfaRequirement(true, graceSeconds, graceSeconds == 0, methods.length > 0, Set.of(methods));
    }

    @Test
    void jwt_graceHonoured_aStampYoungerThanTheGrace_isLetThrough() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(120)));

        stampedAdmin(System.currentTimeMillis() - 30_000L, null).get().uri(GUARDED).exchange()
                .expectStatus().isOk();
    }

    @Test
    void jwt_graceHonoured_aStampOlderThanTheGrace_isDenied_despiteTheAuthority() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(120)));

        stampedAdmin(System.currentTimeMillis() - 121_000L, null).get().uri(GUARDED).exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(RoleMfaPolicyEnforcementFilter.SIGNAL_HEADER, "true");
        verify(service, never()).listEffective(anyString());
    }

    @Test
    void jwt_graceHonoured_anAuthorityWithNoStampClaim_isDenied() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(120)));

        admin("MFA_SATISFIED").get().uri(GUARDED).exchange().expectStatus().isForbidden();
    }

    @Test
    void jwt_graceHonoured_aFutureStamp_isDenied() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(120)));

        stampedAdmin(System.currentTimeMillis() + 60_000L, null).get().uri(GUARDED).exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void jwt_methodsHonoured_anAllowedAmr_isLetThrough_asStringOrList() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(0, "webauthn", "otp")));

        stampedAdmin(System.currentTimeMillis(), "otp").get().uri(GUARDED).exchange().expectStatus().isOk();
        stampedAdmin(System.currentTimeMillis(), List.of("pwd", "webauthn")).get().uri(GUARDED).exchange()
                .expectStatus().isOk();
    }

    @Test
    void jwt_methodsHonoured_aDisallowedOrMissingAmr_isDenied() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(0, "webauthn")));

        stampedAdmin(System.currentTimeMillis(), "otp").get().uri(GUARDED).exchange().expectStatus().isForbidden();
        stampedAdmin(System.currentTimeMillis(), List.of("pwd", "otp")).get().uri(GUARDED).exchange()
                .expectStatus().isForbidden();
        stampedAdmin(System.currentTimeMillis(), null).get().uri(GUARDED).exchange().expectStatus().isForbidden();
        verify(service, never()).listEffective(anyString());
    }

    @Test
    void jwt_withoutTheAuthority_noClaimCanSubstitute() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(120, "otp")));

        web.mutateWith(mockJwt()
                        .jwt(j -> j.issuer(BRANDX_ISS).subject("subj")
                                .claim(Roles.MFA_SATISFIED_AT_CLAIM, Long.toString(System.currentTimeMillis()))
                                .claim("amr", "otp"))
                        .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .get().uri(GUARDED).exchange().expectStatus().isForbidden();
    }

    @Test
    void jwt_platformWindowAndAnyMethod_passOnTheAuthorityAlone() {
        when(service.requirementFor(anyString(), any())).thenReturn(Mono.just(requirement(0)));

        admin("MFA_SATISFIED").get().uri(GUARDED).exchange().expectStatus().isOk();
    }

    @Test
    void jwtEvidence_isAPureFunctionOfTheClaimsAndTheRequirement() {
        var now = System.currentTimeMillis();
        var fresh = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t").header("alg", "none")
                .claim(Roles.MFA_SATISFIED_AT_CLAIM, Long.toString(now - 1_000L)).claim("amr", "otp").build();
        var stale = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t").header("alg", "none")
                .claim(Roles.MFA_SATISFIED_AT_CLAIM, Long.toString(now - 200_000L)).claim("amr", "otp").build();
        var garbage = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t").header("alg", "none")
                .claim(Roles.MFA_SATISFIED_AT_CLAIM, "soon").claim("amr", "otp").build();
        var numeric = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t").header("alg", "none")
                .claim(Roles.MFA_SATISFIED_AT_CLAIM, now - 1_000L).claim("amr", "otp").build();

        assertThat(RoleMfaPolicyEnforcementFilter.jwtEvidence(fresh, requirement(120, "otp"))).isTrue();
        assertThat(RoleMfaPolicyEnforcementFilter.jwtEvidence(numeric, requirement(120, "otp"))).isTrue();
        assertThat(RoleMfaPolicyEnforcementFilter.jwtEvidence(stale, requirement(120, "otp"))).isFalse();
        assertThat(RoleMfaPolicyEnforcementFilter.jwtEvidence(stale, requirement(0, "otp"))).as("0 = no grace re-read").isTrue();
        assertThat(RoleMfaPolicyEnforcementFilter.jwtEvidence(garbage, requirement(120))).isFalse();
        assertThat(RoleMfaPolicyEnforcementFilter.jwtEvidence(garbage, requirement(0))).isTrue();
        assertThat(RoleMfaPolicyEnforcementFilter.jwtEvidence(fresh, requirement(120, "webauthn"))).isFalse();
    }
}
