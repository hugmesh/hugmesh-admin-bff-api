package systems.hugmesh.adminbff.desktop;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.desktop.terminal.DeviceTerminalProperties;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;
import systems.hugmesh.adminbff.workload.WorkloadStepUpService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * BFF-STEPUP web-layer contract for the ADMIN-reachable desktop step-up mint
 * ({@code POST /bff/admin/desktop/step-up}) — the gate-4 unblocker. With the device-terminal leg
 * ENABLED here (so the dark-503 short-circuit is OFF), this isolates: ADMIN+SUPERADMIN reach the
 * mint; MOD/USER 403 (coarse gate, no mint); unauthenticated 401; the operator is the JWT subject
 * (never a body field); an UNLICENSED / non-leader mint refusal from the unchanged
 * {@link WorkloadStepUpService#mint} maps to 403; a successful mint returns {stepUpToken, ttlMinutes}.
 * The ships-dark 503 is pinned in {@link DesktopStepUpControllerDarkTest}.
 *
 * <p>The mint broker is mocked, so this proves the controller's gate + the
 * operator==subject + the 403 mapping in isolation (the license/leader precondition itself lives in
 * — and is unit-tested via — {@link WorkloadStepUpService}).
 */
@WebFluxTest(controllers = DesktopStepUpController.class)
@Import({SecurityConfig.class, DomainRegistry.class, DeviceTerminalProperties.class,
        ValidationExceptionHandler.class, ApiExceptionHandler.class})
@TestPropertySource(properties = "app.device-terminal.enabled=true")
class DesktopStepUpControllerTest {

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

    private WebTestClient asSuperadmin(String subject) {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(subject)).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    // ── ADMIN with license mints (the gate-4 unblocker) ──────────────────────────

    @Test
    void mint_asAdmin_withLicense_returnsTokenAndTtl_operatorIsSubject() {
        when(stepUp.mint(eq("admin-x"), eq("admin-x"))).thenReturn(Mono.just("opaque-token"));
        asAdmin("admin-x").post().uri(URI)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.stepUpToken").isEqualTo("opaque-token")
                .jsonPath("$.ttlMinutes").isEqualTo(WorkloadStepUpService.STEP_UP_TTL.toMinutes());
        // operator == subject == JWT subject, NEVER a body/param.
        verify(stepUp).mint(eq("admin-x"), eq("admin-x"));
    }

    @Test
    void mint_asSuperadmin_unscoped_mints() {
        when(stepUp.mint(eq("super-1"), eq("super-1"))).thenReturn(Mono.just("sa-token"));
        asSuperadmin("super-1").post().uri(URI)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.stepUpToken").isEqualTo("sa-token");
    }

    // ── unlicensed / cross-domain-unlicensed admin cannot mint -> 403 ────────────

    @Test
    void mint_unlicensed_isDeniedBy403() {
        // the unchanged mint refuses an operator with no active SSH license.
        when(stepUp.mint(eq("admin-x"), eq("admin-x"))).thenReturn(Mono.error(
                new WorkloadStepUpService.StepUpDeniedException(
                        "step-up denied: operator holds no active SSH license")));
        asAdmin("admin-x").post().uri(URI)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void mint_nonLeaderReplica_isDeniedBy403() {
        when(stepUp.mint(eq("admin-x"), eq("admin-x"))).thenReturn(Mono.error(
                new WorkloadStepUpService.StepUpDeniedException(
                        "step-up can only be minted by the Lease leader")));
        asAdmin("admin-x").post().uri(URI)
                .exchange().expectStatus().isForbidden();
    }

    // ── MOD / USER -> 403 (coarse gate), never mints ─────────────────────────────

    @Test
    void mint_asMod_isForbidden_neverMints() {
        asMod().post().uri(URI).exchange().expectStatus().isForbidden();
        verify(stepUp, never()).mint(any(), any());
    }

    @Test
    void mint_asUser_isForbidden_neverMints() {
        asUser().post().uri(URI).exchange().expectStatus().isForbidden();
        verify(stepUp, never()).mint(any(), any());
    }

    @Test
    void mint_unauthenticated_is401_neverMints() {
        web.post().uri(URI).exchange().expectStatus().isUnauthorized();
        verify(stepUp, never()).mint(any(), any());
    }
}
