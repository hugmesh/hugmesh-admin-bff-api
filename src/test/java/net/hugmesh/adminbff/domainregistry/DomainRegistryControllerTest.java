package net.hugmesh.adminbff.domainregistry;
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
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.adminbff.web.dto.CreateDomainRequest;

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
 * The DOMAIN-REGISTRY controller role matrix — the acceptance bar for the SUPERADMIN-ONLY
 * boundary on {@code /bff/admin/domains} (multi-tenancy PR9). Mirrors
 * {@code DeviceLicenseControllerTest}: {@code @WebFluxTest} + the real
 * {@link SecurityConfig} so BOTH the coarse path gate ({@code hasAnyRole ADMIN,SUPERADMIN})
 * AND the per-method {@code @PreAuthorize("hasRole('SUPERADMIN')")} run.
 *
 * <ul>
 *   <li>SUPERADMIN — ALLOW on list / get / create / update (cross-domain; not
 *       domain-scoped).</li>
 *   <li>ADMIN — DENY (403) on EVERY endpoint (passes the coarse gate, walled at the
 *       per-method SUPERADMIN gate) + never reaches the service.</li>
 *   <li>MOD / USER — DENY (403) on EVERY endpoint (never clear the coarse gate).</li>
 *   <li>duplicate cluster_domain -&gt; 409; {@code created_by_subject} stamped from the
 *       JWT subject; an update changes fields but not the PK.</li>
 * </ul>
 */
@WebFluxTest(controllers = DomainRegistryController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DomainRegistryControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DomainRegistryService service;
    @MockitoBean DomainRegistryExportService export;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String SUBJECT = "superadmin-subject-42";

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.subject(SUBJECT))
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

    private static DomainRegistration sample() {
        return new DomainRegistration("dom-1", "acme.test", "acme", "Acme Inc", "vault:pki/acme",
                "acme", "acme-org", "tag:acme", true, Instant.now(), SUBJECT, Instant.now());
    }

    private static final String CREATE_BODY = "{"
            + "\"clusterDomain\":\"acme.test\",\"brand\":\"acme\",\"org\":\"Acme Inc\","
            + "\"caRef\":\"vault:pki/acme\",\"nsPrefix\":\"acme\",\"casdoorOrg\":\"acme-org\","
            + "\"meshTag\":\"tag:acme\",\"enabled\":true}";

    private static final String UPDATE_BODY = "{\"brand\":\"renamed\",\"enabled\":false}";

    // ── SUPERADMIN ALLOW ────────────────────────────────────────────────────────

    @Test
    void list_asSuperadmin_isAllowed() {
        when(service.list()).thenReturn(Flux.just(sample()));
        asSuperadmin().get().uri("/bff/admin/domains")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].clusterDomain").isEqualTo("acme.test");
        verify(service).list();
    }

    @Test
    void get_asSuperadmin_isAllowed() {
        when(service.get(eq("acme.test"))).thenReturn(Mono.just(sample()));
        asSuperadmin().get().uri("/bff/admin/domains/acme.test")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.brand").isEqualTo("acme");
        verify(service).get("acme.test");
    }

    @Test
    void create_asSuperadmin_isAllowed_andStampsSubjectFromToken() {
        when(service.create(any(CreateDomainRequest.class), eq(SUBJECT)))
                .thenReturn(Mono.just(sample()));
        asSuperadmin().post().uri("/bff/admin/domains")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isCreated()
                .expectBody().jsonPath("$.clusterDomain").isEqualTo("acme.test")
                .jsonPath("$.createdBySubject").isEqualTo(SUBJECT);
        // created_by_subject is taken from jwt.getSubject(), NOT the request body.
        verify(service).create(any(CreateDomainRequest.class), eq(SUBJECT));
    }

    @Test
    void update_asSuperadmin_isAllowed_changesFieldsNotPk() {
        // The service returns the updated row: same id (PK unchanged), new brand, disabled.
        DomainRegistration updated = new DomainRegistration("dom-1", "acme.test", "renamed",
                "Acme Inc", "vault:pki/acme", "acme", "acme-org", "tag:acme", false,
                Instant.now(), SUBJECT, Instant.now());
        when(service.update(eq("acme.test"), any())).thenReturn(Mono.just(updated));
        asSuperadmin().put().uri("/bff/admin/domains/acme.test")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(UPDATE_BODY)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("dom-1")            // PK unchanged
                .jsonPath("$.clusterDomain").isEqualTo("acme.test") // natural key unchanged
                .jsonPath("$.brand").isEqualTo("renamed")       // mutable field changed
                .jsonPath("$.enabled").isEqualTo(false);        // soft-disable
        verify(service).update(eq("acme.test"), any());
    }

    @Test
    void status_asSuperadmin_isAllowed_carriesProvisioningFields() {
        // The "registered but not yet provisioned" read: the band-190 status fields default
        // false/false/0 and ride the same DomainResponse rows the list returns.
        when(service.list()).thenReturn(Flux.just(sample()));
        asSuperadmin().get().uri("/bff/admin/domains/status")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].clusterDomain").isEqualTo("acme.test")
                .jsonPath("$[0].caProvisioned").isEqualTo(false)
                .jsonPath("$[0].appsetRegistered").isEqualTo(false)
                .jsonPath("$[0].lastReconciledGeneration").isEqualTo(0);
    }

    @Test
    void export_asSuperadmin_isAllowed_returnsTheSignedRegistryExport() {
        DomainExportModels.SignedDomainExport signed = new DomainExportModels.SignedDomainExport(
                new DomainExportModels.DomainExportBody("fp-1", 1L,
                        java.util.List.of(new DomainExportModels.DomainEntry("acme.test", "acme",
                                "Acme Inc", "vault:pki/acme", "acme", "acme-org", "tag:acme",
                                false, false, 0L))),
                "hash", "sig", "pub", true);
        when(export.exportRegistry(eq("fp-1"))).thenReturn(Mono.just(signed));
        asSuperadmin().get().uri("/bff/admin/domains/export?node=fp-1")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.signed").isEqualTo(true)
                .jsonPath("$.body.node").isEqualTo("fp-1")
                .jsonPath("$.body.entries[0].clusterDomain").isEqualTo("acme.test")
                .jsonPath("$.body.entries[0].caRef").isEqualTo("vault:pki/acme");
        verify(export).exportRegistry(eq("fp-1"));
    }

    @Test
    void export_asSuperadmin_withoutNode_isAllowed_unscopedRegistry() {
        DomainExportModels.SignedDomainExport signed = new DomainExportModels.SignedDomainExport(
                new DomainExportModels.DomainExportBody("", 0L, java.util.List.of()),
                "hash", "sig", "pub", true);
        when(export.exportRegistry(eq((String) null))).thenReturn(Mono.just(signed));
        asSuperadmin().get().uri("/bff/admin/domains/export")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.signed").isEqualTo(true);
        verify(export).exportRegistry(eq((String) null));
    }

    @Test
    void create_duplicateClusterDomain_is409_fromServiceGuard() {
        when(service.create(any(CreateDomainRequest.class), anyString()))
                .thenReturn(Mono.error(ApiException.conflict(
                        "domain 'acme.test' is already registered")));
        asSuperadmin().post().uri("/bff/admin/domains")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isEqualTo(409)
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("already registered"));
    }

    @Test
    void create_blankClusterDomain_isBadRequest_andNeverWrites() {
        asSuperadmin().post().uri("/bff/admin/domains")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"clusterDomain\":\"\",\"brand\":\"x\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).create(any(), anyString());
    }

    // ── ADMIN DENY (403) on EVERY endpoint + never reaches the service ───────────

    @Test
    void list_asAdmin_isForbidden() {
        asAdmin().get().uri("/bff/admin/domains").exchange().expectStatus().isForbidden();
        verify(service, never()).list();
    }

    @Test
    void get_asAdmin_isForbidden() {
        asAdmin().get().uri("/bff/admin/domains/acme.test").exchange().expectStatus().isForbidden();
        verify(service, never()).get(anyString());
    }

    @Test
    void create_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/admin/domains")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(any(), anyString());
    }

    @Test
    void update_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().put().uri("/bff/admin/domains/acme.test")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(UPDATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).update(anyString(), any());
    }

    @Test
    void status_asAdmin_isForbidden() {
        asAdmin().get().uri("/bff/admin/domains/status").exchange().expectStatus().isForbidden();
        verify(service, never()).list();
    }

    @Test
    void export_asAdmin_isForbidden_andNeverExports() {
        asAdmin().get().uri("/bff/admin/domains/export?node=fp-1")
                .exchange().expectStatus().isForbidden();
        verify(export, never()).exportRegistry(any());
    }

    // ── MOD DENY (403) on EVERY endpoint ────────────────────────────────────────

    @Test
    void list_asMod_isForbidden() {
        asMod().get().uri("/bff/admin/domains").exchange().expectStatus().isForbidden();
    }

    @Test
    void create_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/admin/domains")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(any(), anyString());
    }

    @Test
    void update_asMod_isForbidden_andNeverWrites() {
        asMod().put().uri("/bff/admin/domains/acme.test")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(UPDATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).update(anyString(), any());
    }

    // ── USER DENY (403) on EVERY endpoint ───────────────────────────────────────

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/domains").exchange().expectStatus().isForbidden();
    }

    @Test
    void get_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/domains/acme.test").exchange().expectStatus().isForbidden();
    }

    @Test
    void create_asUser_isForbidden_andNeverWrites() {
        asUser().post().uri("/bff/admin/domains")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(any(), anyString());
    }

    @Test
    void update_asUser_isForbidden_andNeverWrites() {
        asUser().put().uri("/bff/admin/domains/acme.test")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(UPDATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).update(anyString(), any());
    }

    @Test
    void status_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/domains/status").exchange().expectStatus().isForbidden();
        verify(service, never()).list();
    }

    @Test
    void export_asUser_isForbidden_andNeverExports() {
        asUser().get().uri("/bff/admin/domains/export?node=fp-1")
                .exchange().expectStatus().isForbidden();
        verify(export, never()).exportRegistry(any());
    }

    @Test
    void export_asMod_isForbidden() {
        asMod().get().uri("/bff/admin/domains/export?node=fp-1")
                .exchange().expectStatus().isForbidden();
        verify(export, never()).exportRegistry(any());
    }
}
