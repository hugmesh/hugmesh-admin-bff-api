package systems.hugmesh.adminbff.cloudbackup;
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
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;
import java.util.List;

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
 * The per-domain CLOUD-BACKUPS controller role + step-up matrix — the acceptance bar for the
 * {@code /bff/admin/cloud-backups/**} surface. Mirrors {@code DesktopSudoAdminControllerTest}:
 * {@code @WebFluxTest} + the real {@link SecurityConfig} so BOTH the coarse {@code
 * /bff/admin/**} path gate AND the per-method {@code @PreAuthorize("hasAnyRole(...)")} run.
 *
 * <ul>
 *   <li>ADMIN/SUPERADMIN — ALLOW (list/create/versions/artifacts/services/destinations).</li>
 *   <li>MOD/USER — 403 on EVERY endpoint + never reach the service (mutation-resistant DENY,
 *       {@code verify(never())}).</li>
 *   <li>unauthenticated — 401.</li>
 *   <li>RESTORE — requires a satisfied STEP-UP: no/invalid {@code X-Backup-StepUp} -> 403 +
 *       service never called; valid token -> ALLOW.</li>
 * </ul>
 */
@WebFluxTest(controllers = BackupAdminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class BackupAdminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean BackupService service;
    @MockitoBean BackupStepUpGate stepUp;
    @MockitoBean systems.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean systems.hugmesh.authcore.provision.GatewayRevocationClient revocations;

    private static final String SUBJECT = "admin-subject-9";

    @org.junit.jupiter.api.BeforeEach
    void mfaDarkByDefault() {
        // A5 MFA leg ships dark: no fresh MFA stamp by default, so only the workload
        // step-up token leg satisfies (today's behaviour). The 3-arg unified gate then
        // delegates to the 2-arg token leg the individual tests stub.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(SUBJECT))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(SUBJECT))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static BackupSet set() {
        return new BackupSet("set-1", "domain-brandx", 1L, BackupCloudScope.DOMAIN, "brandx",
                SUBJECT, List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b",
                null, null, BackupSet.STATUS_PENDING, Instant.now(), null, null);
    }

    private static final String CREATE_BODY =
            "{\"services\":[\"postgres\"],\"destinationKind\":\"object_store\","
            + "\"destinationRef\":\"s3://b\"}";

    // ── list ──────────────────────────────────────────────────────────────────────────

    @Test
    void list_asAdmin_isAllowed() {
        when(service.list(any(PrincipalDomain.class), any())).thenReturn(Flux.just(set()));
        asAdmin().get().uri("/bff/admin/cloud-backups").exchange().expectStatus().isOk();
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/cloud-backups").exchange().expectStatus().isForbidden();
        verify(service, never()).list(any(), any());
    }

    @Test
    void list_unauthenticated_is401() {
        web.get().uri("/bff/admin/cloud-backups").exchange().expectStatus().isUnauthorized();
        verify(service, never()).list(any(), any());
    }

    // ── create (DOMAIN scope) ───────────────────────────────────────────────────────────

    @Test
    void create_asAdmin_isAllowed_andOwnerIsSubject() {
        when(service.create(any(), eq(BackupCloudScope.DOMAIN), any(), any(), anyString(), any(),
                eq(SUBJECT), any(PrincipalDomain.class))).thenReturn(Mono.just(set()));
        asAdmin().post().uri("/bff/admin/cloud-backups")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("set-1");
        // created_by == the JWT subject (owner == subject), scope threaded, DOMAIN scope.
        verify(service).create(any(), eq(BackupCloudScope.DOMAIN), any(), any(), anyString(), any(),
                eq(SUBJECT), any(PrincipalDomain.class));
    }

    @Test
    void create_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/admin/cloud-backups")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void create_emptyServices_is400() {
        asAdmin().post().uri("/bff/admin/cloud-backups")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"services\":[],\"destinationKind\":\"object_store\",\"destinationRef\":\"s3://b\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).create(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void create_unknownDestinationKind_is400() {
        asAdmin().post().uri("/bff/admin/cloud-backups")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"services\":[\"postgres\"],\"destinationKind\":\"ftp\",\"destinationRef\":\"x\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).create(any(), any(), any(), any(), any(), any(), any(), any());
    }

    // ── versions / artifacts ─────────────────────────────────────────────────────────────

    @Test
    void versions_asAdmin_isAllowed() {
        when(service.versions(eq("set-1"), any(PrincipalDomain.class))).thenReturn(Flux.just(set()));
        asAdmin().get().uri("/bff/admin/cloud-backups/set-1/versions")
                .exchange().expectStatus().isOk();
    }

    @Test
    void versions_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/cloud-backups/set-1/versions")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).versions(anyString(), any());
    }

    @Test
    void artifacts_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/cloud-backups/set-1/artifacts")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).artifacts(anyString(), any());
    }

    // ── restore (step-up required) ───────────────────────────────────────────────────────

    @Test
    void restore_withSatisfiedStepUp_isAllowed() {
        when(stepUp.isSatisfied(eq(SUBJECT), eq("tok"))).thenReturn(true);
        when(service.restore(eq("set-1"), eq(SUBJECT), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(set()));
        asAdmin().post().uri("/bff/admin/cloud-backups/set-1/restore")
                .header(BackupStepUpGate.STEP_UP_HEADER, "tok")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.status").isEqualTo("RESTORE_QUEUED");
        verify(service).restore(eq("set-1"), eq(SUBJECT), any(PrincipalDomain.class));
    }

    @Test
    void restore_withoutStepUpHeader_is403_andNeverRestores() {
        // no X-Backup-StepUp -> the gate is not satisfied -> 403 "requires step-up".
        when(stepUp.isSatisfied(anyString(), any())).thenReturn(false);
        asAdmin().post().uri("/bff/admin/cloud-backups/set-1/restore")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("requires step-up"));
        verify(service, never()).restore(anyString(), anyString(), any());
    }

    @Test
    void restore_withInvalidStepUp_is403_andNeverRestores() {
        when(stepUp.isSatisfied(eq(SUBJECT), eq("bad"))).thenReturn(false);
        asAdmin().post().uri("/bff/admin/cloud-backups/set-1/restore")
                .header(BackupStepUpGate.STEP_UP_HEADER, "bad")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).restore(anyString(), anyString(), any());
    }

    @Test
    void restore_asUser_isForbidden_andNeverRestores() {
        asUser().post().uri("/bff/admin/cloud-backups/set-1/restore")
                .header(BackupStepUpGate.STEP_UP_HEADER, "tok")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).restore(anyString(), anyString(), any());
    }

    @Test
    void restore_crossDomainOutOfScope_is404() {
        // a scoped admin restoring an out-of-scope id: the service's scoped re-resolve yields
        // empty -> IllegalArgumentException -> 404 (not visible).
        when(stepUp.isSatisfied(eq(SUBJECT), eq("tok"))).thenReturn(true);
        when(service.restore(eq("other-brand-set"), eq(SUBJECT), any(PrincipalDomain.class)))
                .thenReturn(Mono.error(new IllegalArgumentException(
                        "backup set other-brand-set not found in your scope")));
        asAdmin().post().uri("/bff/admin/cloud-backups/other-brand-set/restore")
                .header(BackupStepUpGate.STEP_UP_HEADER, "tok")
                .exchange().expectStatus().isNotFound();
    }

    // ── services menu ────────────────────────────────────────────────────────────────────

    @Test
    void services_asAdmin_isAllowed() {
        when(service.services(any(PrincipalDomain.class)))
                .thenReturn(Flux.just(new RunningService("postgres", "PG",
                        BackupArtifact.KIND_DB_DUMP, false)));
        asAdmin().get().uri("/bff/admin/cloud-backups/services")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].key").isEqualTo("postgres");
    }

    @Test
    void services_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/cloud-backups/services")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).services(any());
    }

    // ── destinations ──────────────────────────────────────────────────────────────────────

    @Test
    void getDestination_asAdmin_isAllowed() {
        when(service.destination(any(PrincipalDomain.class), any())).thenReturn(Mono.empty());
        asAdmin().get().uri("/bff/admin/cloud-backups/destinations")
                .exchange().expectStatus().isNoContent();
    }

    @Test
    void putDestination_asAdmin_isAllowed() {
        when(service.putDestination(eq(BackupDestinationKind.OBJECT_STORE), eq("s3://b"), any(),
                anyString(), any(PrincipalDomain.class), any()))
                .thenReturn(Mono.just(new BackupDestination("d1", BackupDestinationKind.OBJECT_STORE,
                        "s3://b", null, "brandx", SUBJECT, Instant.now(), null)));
        asAdmin().put().uri("/bff/admin/cloud-backups/destinations")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"object_store\",\"destinationRef\":\"s3://b\"}")
                .exchange().expectStatus().isOk();
    }

    @Test
    void putDestination_asUser_isForbidden_andNeverWrites() {
        asUser().put().uri("/bff/admin/cloud-backups/destinations")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"object_store\",\"destinationRef\":\"s3://b\"}")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).putDestination(any(), any(), any(), any(), any(), any());
    }
}
