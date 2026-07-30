package systems.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.servicecatalog.federation.ServiceCatalogFederationService;
import systems.hugmesh.adminbff.servicecatalog.scaffold.ScaffoldService;
import systems.hugmesh.adminbff.servicecatalog.scaffold.ServiceScaffold;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;
import systems.hugmesh.commons.security.DomainRegistry;

import java.time.Instant;
import java.util.List;
import java.util.Map;

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
 * Web-layer contract for the Service-Store wizard endpoints — the SUPERADMIN-only role gate on
 * EVERY endpoint, the STEP-UP requirement on the two mutating verbs (scaffold create + federate),
 * and the archive ZIP + federate outcome shapes. {@code @WebFluxTest} + the real
 * {@link SecurityConfig} so BOTH the coarse {@code /bff/superadmin/**} gate AND the per-method
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} run. Services + the step-up gate are mocked so
 * the controller's gates are isolated; {@code verify(..., never())} backs each deny (the
 * controller REFUSES before ever calling the service).
 */
@WebFluxTest(controllers = ServiceStoreWizardController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class ServiceStoreWizardControllerTest {

    private static final String STEP_UP = ServiceStoreStepUpGate.STEP_UP_HEADER;
    private static final String TOKEN = "good-token";
    private static final String SUBJECT = "superadmin-subject-11";

    private static final String SCAFFOLD_BODY = """
            {"serviceKey":"owncast","displayName":"Owncast","archetype":"spring-bff",
             "mountAt":"/owncast","requiresRole":"ROLE_OWNCAST"}""";
    private static final String FEDERATE_BODY = """
            {"slug":"owncast","mountAt":"/owncast","exposedModule":"./routes",
             "remoteEntryUrl":"https://cdn.acme.test/owncast/remoteEntry.json",
             "kind":"remote-shell","visibility":"internal","requiresRole":"ROLE_OWNCAST"}""";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ScaffoldService scaffold;
    @MockitoBean ServiceDeploymentRepository deployments;
    @MockitoBean ServiceCatalogFederationService federation;
    @MockitoBean ServiceStoreStepUpGate stepUp;
    @MockitoBean systems.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void mfaDarkByDefault() {
        // A5 MFA leg ships DARK: no fresh stamp, nothing to consume — only the workload step-up
        // token leg satisfies. The 3-arg unified gate delegates to the 2-arg token leg.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(SUBJECT)).authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static ServiceScaffold scaffoldRow() {
        return new ServiceScaffold("scaf-1", "acme.test", "owncast", "spring-bff", "Owncast",
                "/owncast", "ROLE_OWNCAST", ServiceScaffold.STATE_REQUESTED, SUBJECT,
                Instant.now(), Instant.now());
    }

    private static ServiceDeployment deployment() {
        return new ServiceDeployment("dep-1", "acme.test", "owncast", "small-postgres",
                ServiceDeployment.STATE_ACTIVE, Instant.now(), null, "teardown,alert",
                ServiceDeployment.PROP_PENDING, null, SUBJECT);
    }

    // ── archetypes (read; SUPERADMIN-only) ───────────────────────────────────────
    @Test
    void archetypes_superadmin_returnsCatalog() {
        when(scaffold.archetypes()).thenReturn(List.of(
                new systems.hugmesh.adminbff.servicecatalog.scaffold.ScaffoldArchetype(
                        "spring-bff", "Spring Boot BFF", "desc", "backend")));
        asSuperadmin().get().uri("/bff/superadmin/service-store/scaffold/archetypes")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].name").isEqualTo("spring-bff")
                .jsonPath("$[0].kind").isEqualTo("backend");
    }

    @Test
    void archetypes_admin_403_noServiceCall() {
        asAdmin().get().uri("/bff/superadmin/service-store/scaffold/archetypes")
                .exchange().expectStatus().isForbidden();
        verify(scaffold, never()).archetypes();
    }

    @Test
    void archetypes_unauthenticated_401() {
        web.get().uri("/bff/superadmin/service-store/scaffold/archetypes")
                .exchange().expectStatus().isUnauthorized();
        verify(scaffold, never()).archetypes();
    }

    // ── federation status (read; SUPERADMIN-only) ────────────────────────────────
    @Test
    void federationStatus_superadmin_carriesEnabledFlag() {
        when(federation.status()).thenReturn(Map.of("enabled", false,
                "warnings", List.of("federation registration ships dark")));
        asSuperadmin().get().uri("/bff/superadmin/service-store/federation")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.enabled").isEqualTo(false)
                .jsonPath("$.warnings[0]").value(org.hamcrest.Matchers.containsString("ships dark"));
    }

    @Test
    void federationStatus_admin_403() {
        asAdmin().get().uri("/bff/superadmin/service-store/federation")
                .exchange().expectStatus().isForbidden();
        verify(federation, never()).status();
    }

    // ── scaffold create: role + step-up gates ────────────────────────────────────
    @Test
    void createScaffold_superadmin_withStepUp_201() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(scaffold.create(eq("acme.test"), eq("owncast"), eq("spring-bff"), eq("Owncast"),
                eq("/owncast"), eq("ROLE_OWNCAST"), eq(SUBJECT))).thenReturn(Mono.just(scaffoldRow()));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/scaffold")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SCAFFOLD_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.serviceKey").isEqualTo("owncast")
                .jsonPath("$.archetype").isEqualTo("spring-bff")
                .jsonPath("$.state").isEqualTo("requested")
                .jsonPath("$.createdBySubject").isEqualTo(SUBJECT);
        // domain from PATH; subject from TOKEN.
        verify(scaffold).create("acme.test", "owncast", "spring-bff", "Owncast", "/owncast",
                "ROLE_OWNCAST", SUBJECT);
    }

    @Test
    void createScaffold_missingStepUp_403_noServiceCall() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/scaffold")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SCAFFOLD_BODY)
                .exchange().expectStatus().isForbidden();
        verify(scaffold, never()).create(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void createScaffold_admin_403_noServiceCall() {
        asAdmin().post().uri("/bff/superadmin/service-store/acme.test/scaffold")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SCAFFOLD_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(scaffold, never()).create(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void createScaffold_user_403() {
        asUser().post().uri("/bff/superadmin/service-store/acme.test/scaffold")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SCAFFOLD_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(scaffold, never()).create(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void createScaffold_unauthenticated_401() {
        web.post().uri("/bff/superadmin/service-store/acme.test/scaffold")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SCAFFOLD_BODY)
                .exchange().expectStatus().isUnauthorized();
        verify(scaffold, never()).create(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void createScaffold_invalidArchetypePattern_400_noServiceCall() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/scaffold")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"serviceKey\":\"owncast\",\"archetype\":\"Bad Arch!\"}")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isBadRequest();
        verify(scaffold, never()).create(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void createScaffold_blankServiceKey_400_noServiceCall() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/scaffold")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"serviceKey\":\"\",\"archetype\":\"spring-bff\"}")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isBadRequest();
        verify(scaffold, never()).create(any(), any(), any(), any(), any(), any(), any());
    }

    // ── scaffold archive (read; SUPERADMIN-only; application/zip) ─────────────────
    @Test
    void scaffoldArchive_superadmin_returnsZip() {
        byte[] zip = {0x50, 0x4b, 0x03, 0x04, 0x01, 0x02};
        when(scaffold.archive(eq("acme.test"), eq("scaf-1"))).thenReturn(Mono.just(zip));
        asSuperadmin().get().uri("/bff/superadmin/service-store/acme.test/scaffold/scaf-1/archive")
                .accept(MediaType.parseMediaType("application/zip"))
                .exchange().expectStatus().isOk()
                .expectHeader().contentType(MediaType.parseMediaType("application/zip"))
                .expectHeader().value("Content-Disposition",
                        org.hamcrest.Matchers.containsString("scaf-1-scaffold.zip"))
                .expectBody(byte[].class).isEqualTo(zip);
        verify(scaffold).archive("acme.test", "scaf-1");
    }

    @Test
    void scaffoldArchive_admin_403_noServiceCall() {
        asAdmin().get().uri("/bff/superadmin/service-store/acme.test/scaffold/scaf-1/archive")
                .exchange().expectStatus().isForbidden();
        verify(scaffold, never()).archive(any(), any());
    }

    // ── federate: role + step-up gates + outcome ─────────────────────────────────
    @Test
    void federate_superadmin_withStepUp_noopPath_federationRealFalse() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(deployments.findById(eq("dep-1"))).thenReturn(Mono.just(deployment()));
        // Noop federation client: federationReal=false, gitopsDescriptorPending always true.
        when(federation.federate(any(ServiceDeployment.class), any()))
                .thenReturn(Mono.just(new FederateOutcome(deployment(), false, true)));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/federate")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(FEDERATE_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.deployment.serviceKey").isEqualTo("owncast")
                .jsonPath("$.federationReal").isEqualTo(false)
                .jsonPath("$.gitopsDescriptorPending").isEqualTo(true);
        verify(federation).federate(any(ServiceDeployment.class), any());
    }

    @Test
    void federate_missingStepUp_403_noLoadOrFederate() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/federate")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(FEDERATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(deployments, never()).findById(any());
        verify(federation, never()).federate(any(), any());
    }

    @Test
    void federate_admin_403_noLoadOrFederate() {
        asAdmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/dep-1/federate")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(FEDERATE_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(deployments, never()).findById(any());
        verify(federation, never()).federate(any(), any());
    }

    @Test
    void federate_unknownDeployment_404() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(deployments.findById(eq("nope"))).thenReturn(Mono.empty());
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/deployments/nope/federate")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(FEDERATE_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isNotFound();
        verify(federation, never()).federate(any(), any());
    }

    @Test
    void federate_domainMismatch_400_noFederate() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        // The loaded deployment is in acme.test but the path targets other.test.
        when(deployments.findById(eq("dep-1"))).thenReturn(Mono.just(deployment()));
        asSuperadmin().post().uri("/bff/superadmin/service-store/other.test/deployments/dep-1/federate")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(FEDERATE_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isBadRequest();
        verify(federation, never()).federate(any(), any());
    }
}
