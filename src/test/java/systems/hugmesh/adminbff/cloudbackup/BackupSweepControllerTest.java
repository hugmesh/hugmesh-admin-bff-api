package systems.hugmesh.adminbff.cloudbackup;
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
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The on-demand sweep trigger SUPERADMIN-only boundary on
 * {@code POST /bff/superadmin/cloud-backups/sweep}. {@code @WebFluxTest} + the real
 * {@link SecurityConfig} so BOTH the coarse {@code /bff/superadmin/**} path gate AND the per-method
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} run. The {@code app.backups.effector.enabled=true}
 * property is set so the gated controller bean is registered at all (it is ABSENT — route 404 — by
 * default, the ships-dark behaviour, which {@link BackupStatusReconcilerWiringTest} covers).
 *
 * <ul>
 *   <li>SUPERADMIN — ALLOW; runs one sweep, returns the reconciled count.</li>
 *   <li>SUPERADMIN + cluster unreachable — the propagated sweep failure surfaces as 503 (NOT a
 *       misleading {@code 200 {"reconciled":0}}).</li>
 *   <li>ADMIN / MOD / USER — 403 + never reaches the reconciler.</li>
 *   <li>unauthenticated — 401.</li>
 * </ul>
 */
@WebFluxTest(controllers = BackupSweepController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
@TestPropertySource(properties = "app.backups.effector.enabled=true")
class BackupSweepControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean BackupStatusReconciler reconciler;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject("super-1"))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    void sweep_asSuperadmin_isAllowed_andReturnsCount() {
        when(reconciler.sweepNow()).thenReturn(Mono.just(2L));
        asSuperadmin().post().uri("/bff/superadmin/cloud-backups/sweep")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.reconciled").isEqualTo(2);
        verify(reconciler).sweepNow();
    }

    @Test
    void sweep_asSuperadmin_clusterUnreachable_surfacesAs503_notReconciledZero() {
        // The manual path propagates a cluster-read failure (unlike the swallow-and-retry scheduled
        // loop), so an operator gets 503 — distinct from a misleading 200 {"reconciled":0}.
        when(reconciler.sweepNow())
                .thenReturn(Mono.error(new IllegalStateException("cluster down")));
        asSuperadmin().post().uri("/bff/superadmin/cloud-backups/sweep")
                .exchange().expectStatus().isEqualTo(503);
        verify(reconciler).sweepNow();
    }

    @Test
    void sweep_asAdmin_isForbidden_andNeverRuns() {
        asAdmin().post().uri("/bff/superadmin/cloud-backups/sweep")
                .exchange().expectStatus().isForbidden();
        verify(reconciler, never()).sweepNow();
    }

    @Test
    void sweep_asMod_isForbidden_andNeverRuns() {
        asMod().post().uri("/bff/superadmin/cloud-backups/sweep")
                .exchange().expectStatus().isForbidden();
        verify(reconciler, never()).sweepNow();
    }

    @Test
    void sweep_asUser_isForbidden_andNeverRuns() {
        asUser().post().uri("/bff/superadmin/cloud-backups/sweep")
                .exchange().expectStatus().isForbidden();
        verify(reconciler, never()).sweepNow();
    }

    @Test
    void sweep_unauthenticated_is401() {
        web.post().uri("/bff/superadmin/cloud-backups/sweep")
                .exchange().expectStatus().isUnauthorized();
        verify(reconciler, never()).sweepNow();
    }
}
