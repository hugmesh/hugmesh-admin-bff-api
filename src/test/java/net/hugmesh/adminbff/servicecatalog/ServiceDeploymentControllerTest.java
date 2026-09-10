package net.hugmesh.adminbff.servicecatalog;
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
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
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
 *
 * <p>{@code provision} — the verb that actually drives infrastructure — is additionally STEP-UP
 * gated, so a superadmin with no {@code X-ServiceStore-StepUp} token and no fresh MFA stamp gets
 * the "requires step-up" 403 the merged catalog-ui slice renders its challenge on, and neither the
 * repository nor the effector is touched. {@code create}/{@code end} write accounting rows only and
 * stay role-only.
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
    @MockitoBean ServiceStoreStepUpGate stepUp;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String SUBJECT = "superadmin-subject-11";
    private static final Instant ENDING = Instant.parse("2030-01-01T00:00:00Z");
    private static final String STEP_UP = ServiceStoreStepUpGate.STEP_UP_HEADER;
    private static final String TOKEN = "good-token";

    @BeforeEach
    void mfaDarkByDefault() {
        // A5 MFA leg ships DARK by default here: only the workload step-up token leg satisfies.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
    }

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
    void provision_asSuperadmin_withStepUp_loadsDeployment_andDrivesEffector() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(repo.findById(eq("dep-1"))).thenReturn(Mono.just(active()));
        when(effector.provision(any(ServiceDeployment.class), any(ServiceSource.class)))
                .thenReturn(Mono.just("acme-test-owncast"));
        // NoopArgoCdClient default: isEffectorReal() returns false.
        when(effector.isEffectorReal()).thenReturn(false);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.deployment.serviceKey").isEqualTo("owncast");
        verify(effector).provision(any(ServiceDeployment.class), any(ServiceSource.class));
    }

    @Test
    void provision_asAdmin_isForbidden_andNeverLoadsOrEffects() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);   // the ROLE is what denies
        asAdmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).findById(anyString());
        verify(effector, never()).provision(any(), any());
    }

    @Test
    void provision_domainMismatch_isBadRequest() {
        // The loaded deployment is in acme.test but the path targets other.test.
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(repo.findById(eq("dep-1"))).thenReturn(Mono.just(active()));
        asSuperadmin().post().uri("/bff/superadmin/service-store/other.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isBadRequest();
        verify(effector, never()).provision(any(), any());
    }

    /** The denial the merged catalog-ui slice consumes: 403 + "requires step-up" (what
     *  {@code ServiceCatalogApiError.isStepUpRequired} matches) + the structured
     *  {@code X-Step-Up-Required} signal naming the retry header. Nothing is loaded or effected. */
    @Test
    void provision_asSuperadmin_withoutStepUp_is403WithTheChallengeContract_andNeverEffects() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .exchange().expectStatus().isForbidden()
                .expectHeader().valueEquals("X-Step-Up-Required", STEP_UP)
                .expectBody().jsonPath("$.error").value(org.hamcrest.Matchers.matchesPattern(
                        "(?i).*requires step-up.*"));
        verify(repo, never()).findById(anyString());
        verify(effector, never()).provision(any(), any());
    }

    @Test
    void provision_withAWrongStepUpToken_is403_andNeverEffects() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);   // only THIS token is valid
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .header(STEP_UP, "stale-token")
                .exchange().expectStatus().isForbidden();
        verify(repo, never()).findById(anyString());
        verify(effector, never()).provision(any(), any());
    }

    /** The co-equal MFA leg satisfies with no token, and is CONSUMED so a second provision in the
     *  freshness window needs its own challenge. */
    @Test
    void provision_withFreshMfaAndNoToken_isAllowed_andConsumesTheStamp() {
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(true));
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        when(repo.findById(eq("dep-1"))).thenReturn(Mono.just(active()));
        when(effector.provision(any(ServiceDeployment.class), any(ServiceSource.class)))
                .thenReturn(Mono.just("acme-test-owncast"));
        when(effector.isEffectorReal()).thenReturn(false);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .exchange().expectStatus().isOk();
        verify(effector).provision(any(ServiceDeployment.class), any(ServiceSource.class));
        verify(mfaStepUp).consume(any());
    }

    /** create / end write accounting rows only and are deliberately NOT step-up gated — pinned so
     *  a later "gate everything" pass is a deliberate decision, not a silent one. */
    @Test
    void create_and_end_needNoStepUp() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        when(service.create(eq("acme.test"), eq("owncast"), eq("small-postgres"),
                eq(ENDING), eq("teardown,alert"), eq(SUBJECT))).thenReturn(Mono.just(active()));
        when(service.end(eq("dep-1"))).thenReturn(Mono.just(active()));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isCreated();
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/end")
                .exchange().expectStatus().isOk();
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
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(repo.findById(eq("dep-1"))).thenReturn(Mono.just(active()));
        when(effector.provision(any(ServiceDeployment.class), any(ServiceSource.class)))
                .thenReturn(Mono.just("acme-test-owncast"));
        when(effector.isEffectorReal()).thenReturn(false);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.deployment.serviceKey").isEqualTo("owncast")
                .jsonPath("$.effectorReal").isEqualTo(false);
    }

    @Test
    void provision_includesEffectorReal_true() {
        // With a real ArgoCD client mock the provision response carries effectorReal:true.
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(repo.findById(eq("dep-1"))).thenReturn(Mono.just(active()));
        when(effector.provision(any(ServiceDeployment.class), any(ServiceSource.class)))
                .thenReturn(Mono.just("acme-test-owncast"));
        // Simulate a real ArgoCD client being active (e.g. RestArgoCdClient wired).
        when(effector.isEffectorReal()).thenReturn(true);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/provision")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(PROVISION_BODY)
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.deployment.serviceKey").isEqualTo("owncast")
                .jsonPath("$.effectorReal").isEqualTo(true);
    }
}
