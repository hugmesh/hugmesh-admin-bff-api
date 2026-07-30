package systems.hugmesh.adminbff.servicecatalog;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The App-Store DEPLOYMENT controller role matrix — SUPERADMIN-ONLY boundary on
 * {@code /bff/superadmin/service-store/{domain}/deployments} + list/create/end behaviour.
 * {@code @WebFluxTest} + the real {@link SecurityConfig} so BOTH the coarse
 * {@code /bff/superadmin/**} gate AND the per-method {@code @PreAuthorize("hasRole
 * ('SUPERADMIN')")} run.
 *
 * <ul>
 *   <li>SUPERADMIN — ALLOW on list/create/end; the {@code domain} is the PATH target;
 *       {@code created_by_subject} stamped from the JWT subject; created records
 *       created_at + ending_at + enforce_actions.</li>
 *   <li>ADMIN / MOD / USER — DENY (403) on EVERY endpoint + never reaches the service.</li>
 * </ul>
 */
@WebFluxTest(controllers = {ServiceDeploymentController.class, ServiceCatalogEffectorController.class})
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class ServiceDeploymentControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ServiceDeploymentService service;
    @MockitoBean ServiceDeploymentRepository repo;
    @MockitoBean AddServiceEffector effector;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String SUBJECT = "superadmin-subject-11";
    private static final Instant ENDING = Instant.parse("2030-01-01T00:00:00Z");

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(SUBJECT))
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

    private static ServiceDeployment active() {
        return new ServiceDeployment("dep-1", "acme.test", "owncast", "small-postgres",
                ServiceDeployment.STATE_ACTIVE, Instant.now(), ENDING, "teardown,alert",
                ServiceDeployment.PROP_PENDING, null, SUBJECT);
    }

    private static final String CREATE_BODY = "{"
            + "\"serviceKey\":\"owncast\",\"profileRef\":\"small-postgres\","
            + "\"endingAt\":\"2030-01-01T00:00:00Z\",\"enforceActions\":\"teardown,alert\"}";

    // ── SUPERADMIN ALLOW ────────────────────────────────────────────────────────

    @Test
    void list_asSuperadmin_isAllowed() {
        when(service.listForDomain(eq("acme.test"))).thenReturn(Flux.just(active()));
        asSuperadmin().get().uri("/bff/superadmin/service-store/acme.test/deployments")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].serviceKey").isEqualTo("owncast");
        verify(service).listForDomain("acme.test");
    }

    @Test
    void create_asSuperadmin_isAllowed_recordsClockAndActions_andStampsSubject() {
        when(service.create(eq("acme.test"), eq("owncast"), eq("small-postgres"),
                eq(ENDING), eq("teardown,alert"), eq(SUBJECT))).thenReturn(Mono.just(active()));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.serviceKey").isEqualTo("owncast")
                .jsonPath("$.state").isEqualTo("active")
                .jsonPath("$.createdAt").exists()
                .jsonPath("$.endingAt").exists()
                .jsonPath("$.enforceActions").isEqualTo("teardown,alert")
                .jsonPath("$.createdBySubject").isEqualTo(SUBJECT);
        // domain from PATH; subject from TOKEN; ending_at + enforce_actions recorded.
        verify(service).create("acme.test", "owncast", "small-postgres", ENDING, "teardown,alert", SUBJECT);
    }

    @Test
    void end_asSuperadmin_isAllowed() {
        ServiceDeployment ended = new ServiceDeployment("dep-1", "acme.test", "owncast",
                "small-postgres", ServiceDeployment.STATE_ENDED, Instant.now(), ENDING,
                "teardown,alert", ServiceDeployment.PROP_APPLIED, Instant.now(), SUBJECT);
        when(service.end(eq("dep-1"))).thenReturn(Mono.just(ended));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/end")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.state").isEqualTo("ended");
        verify(service).end("dep-1");
    }

    @Test
    void create_blankServiceKey_isBadRequest_andNeverWrites() {
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"serviceKey\":\"\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).create(anyString(), anyString(), any(), any(), any(), anyString());
    }

    // ── ADMIN DENY (403) on EVERY endpoint + never reaches the service ───────────

    @Test
    void list_asAdmin_isForbidden() {
        asAdmin().get().uri("/bff/superadmin/service-store/acme.test/deployments")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).listForDomain(anyString());
    }

    @Test
    void create_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/superadmin/service-store/acme.test/deployments")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(anyString(), anyString(), any(), any(), any(), anyString());
    }

    @Test
    void end_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/end")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).end(anyString());
    }

    // ── MOD / USER DENY (403) ───────────────────────────────────────────────────

    @Test
    void create_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/superadmin/service-store/acme.test/deployments")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(anyString(), anyString(), any(), any(), any(), anyString());
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/superadmin/service-store/acme.test/deployments")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).listForDomain(anyString());
    }

    // ── PROVISION (the AddService effector trigger) ──────────────────────────────

    private static final String PROVISION_BODY = "{"
            + "\"sourceKind\":\"GIT\",\"repoUrl\":\"https://forgejo/acme/owncast\","
            + "\"path\":\"deploy/\",\"targetRevision\":\"HEAD\"}";

    @Test
    void provision_asSuperadmin_loadsDeployment_andDrivesEffector() {
        when(repo.findById(eq("dep-1"))).thenReturn(Mono.just(active()));
        when(effector.provision(any(ServiceDeployment.class), any(ServiceSource.class)))
                .thenReturn(Mono.just("acme-test-owncast"));
        // NoopArgoCdClient default: isEffectorReal() returns false.
        when(effector.isEffectorReal()).thenReturn(false);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.deployment.serviceKey").isEqualTo("owncast");
        verify(effector).provision(any(ServiceDeployment.class), any(ServiceSource.class));
    }

    @Test
    void provision_asAdmin_isForbidden_andNeverLoadsOrEffects() {
        asAdmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).findById(anyString());
        verify(effector, never()).provision(any(), any());
    }

    @Test
    void provision_domainMismatch_isBadRequest() {
        // The loaded deployment is in acme.test but the path targets other.test.
        when(repo.findById(eq("dep-1"))).thenReturn(Mono.just(active()));
        asSuperadmin().post().uri("/bff/superadmin/service-store/other.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .exchange().expectStatus().isBadRequest();
        verify(effector, never()).provision(any(), any());
    }

    // ── Effector mode endpoint ───────────────────────────────────────────────────

    @Test
    void effectorMode_returnsFalse_forNoop() {
        // NoopArgoCdClient (the default ships-dark client) reports isEffectorReal() = false.
        when(effector.isEffectorReal()).thenReturn(false);
        asSuperadmin().get().uri("/bff/superadmin/service-store/effector")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.real").isEqualTo(false);
    }

    @Test
    void effectorMode_requiresSuperadmin() {
        // Non-superadmin (ADMIN role) must receive 403 — never reaches the effector.
        asAdmin().get().uri("/bff/superadmin/service-store/effector")
                .exchange().expectStatus().isForbidden();
        verify(effector, never()).isEffectorReal();
    }

    @Test
    void provision_includesEffectorReal_false() {
        // With the noop client the provision response wraps deployment + effectorReal:false.
        when(repo.findById(eq("dep-1"))).thenReturn(Mono.just(active()));
        when(effector.provision(any(ServiceDeployment.class), any(ServiceSource.class)))
                .thenReturn(Mono.just("acme-test-owncast"));
        when(effector.isEffectorReal()).thenReturn(false);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.deployment.serviceKey").isEqualTo("owncast")
                .jsonPath("$.effectorReal").isEqualTo(false);
    }

    @Test
    void provision_includesEffectorReal_true() {
        // With a real ArgoCD client mock the provision response carries effectorReal:true.
        when(repo.findById(eq("dep-1"))).thenReturn(Mono.just(active()));
        when(effector.provision(any(ServiceDeployment.class), any(ServiceSource.class)))
                .thenReturn(Mono.just("acme-test-owncast"));
        // Simulate a real ArgoCD client being active (e.g. RestArgoCdClient wired).
        when(effector.isEffectorReal()).thenReturn(true);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.deployment.serviceKey").isEqualTo("owncast")
                .jsonPath("$.effectorReal").isEqualTo(true);
    }
}
