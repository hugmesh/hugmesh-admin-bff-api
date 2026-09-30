package net.hugmesh.adminbff.domainregistry;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
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

    /** A decision-29 row: idp=own and an allocated MCS pair, as the writer stores them. */
    private static DomainRegistration ownSample() {
        return new DomainRegistration("dom-2", "own.test", "own", "Own Ltd", "vault:pki/own",
                "own", "own-org", "tag:own", true, Instant.now(), SUBJECT, Instant.now(),
                false, false, 0L, DomainIdp.OWN, "s0:c256", "s0:c257");
    }

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
                                false, false, 0L,
                                DomainIdp.OWN, "s0:c256", "s0:c257", null, null))),
                "hash", "sig", "pub", true);
        when(export.exportRegistry(eq("fp-1"))).thenReturn(Mono.just(signed));
        asSuperadmin().get().uri("/bff/admin/domains/export?node=fp-1")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.signed").isEqualTo(true)
                .jsonPath("$.body.node").isEqualTo("fp-1")
                .jsonPath("$.body.entries[0].clusterDomain").isEqualTo("acme.test")
                .jsonPath("$.body.entries[0].caRef").isEqualTo("vault:pki/acme")
                // DECISION 29b/29c on the SERIALIZED wire — these are the exact jq paths
                // hugmesh-generator specs/usr/sbin/hugmesh-domain-reconcile:413 reads
                // (.body.entries[i].idp) and the 05b element fields the per-domain Casdoor
                // needs. A field the JSON does not carry reaches no node.
                .jsonPath("$.body.entries[0].idp").isEqualTo("own")
                .jsonPath("$.body.entries[0].selinuxLevel").isEqualTo("s0:c256")
                .jsonPath("$.body.entries[0].selinuxLevelPg").isEqualTo("s0:c257");
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
    // ── decision 29 (2026-09-17) on the wire ────────────────────────────────────

    @Test
    void create_withIdpOwn_bindsIdpFromTheBody_andTheResponseCarriesTheAllocatedPair() {
        // The SUPERADMIN chooses idp; the MCS pair is NOT theirs to choose — the writer
        // allocated it and the console reads it back here (decision 29b + 29c).
        when(service.create(any(CreateDomainRequest.class), eq(SUBJECT)))
                .thenReturn(Mono.just(ownSample()));
        asSuperadmin().post().uri("/bff/admin/domains")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"clusterDomain\":\"own.test\",\"brand\":\"own\","
                        + "\"nsPrefix\":\"own\",\"casdoorOrg\":\"own-org\",\"idp\":\"own\"}")
                .exchange().expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.idp").isEqualTo("own")
                .jsonPath("$.nsPrefix").isEqualTo("own")
                .jsonPath("$.selinuxLevel").isEqualTo("s0:c256")
                .jsonPath("$.selinuxLevelPg").isEqualTo("s0:c257");

        ArgumentCaptor<CreateDomainRequest> captor =
                ArgumentCaptor.forClass(CreateDomainRequest.class);
        verify(service).create(captor.capture(), eq(SUBJECT));
        assertThat(captor.getValue().idp())
                .as("idp must reach the service from the body, not be defaulted at the edge")
                .isEqualTo("own");
        assertThat(captor.getValue().nsPrefix()).isEqualTo("own");
    }

    @Test
    void list_carriesIdpAndTheMcsPair_soTheConsoleCanShowWhatWasAllocated() {
        when(service.list()).thenReturn(Flux.just(ownSample()));
        asSuperadmin().get().uri("/bff/admin/domains")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].idp").isEqualTo("own")
                .jsonPath("$[0].selinuxLevel").isEqualTo("s0:c256")
                .jsonPath("$[0].selinuxLevelPg").isEqualTo("s0:c257");
    }

    @Test
    void aPreDecisionRow_readsBackWithNoMcsPair_whichIsHowUnprovisionableIsVisible() {
        // sample() is the 12-arg (pre-decision) shape: idp falls to the superdomain floor and
        // the MCS pair is null. That null IS the signal — it is how the console tells a row
        // that cannot be provisioned yet from one that can.
        when(service.list()).thenReturn(Flux.just(sample()));
        asSuperadmin().get().uri("/bff/admin/domains")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].idp").isEqualTo("superdomain")
                .jsonPath("$[0].selinuxLevel").doesNotExist();
    }

    // ── allocate-now (decision 89c) ───────────────────────────────────────────────────

    @Test
    void allocateNow_asSuperadmin_passesTheBodySlugAndTheActor() {
        when(service.allocateNow("legacy.test", "legacy", SUBJECT)).thenReturn(Mono.just(ownSample()));
        asSuperadmin().post().uri("/bff/admin/domains/legacy.test/allocate")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"nsPrefix\":\"legacy\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.selinuxLevel").isEqualTo("s0:c256");
        verify(service).allocateNow("legacy.test", "legacy", SUBJECT);
    }

    @Test
    void allocateNow_withoutABody_passesNoSlug() {
        when(service.allocateNow("legacy.test", null, SUBJECT)).thenReturn(Mono.just(ownSample()));
        asSuperadmin().post().uri("/bff/admin/domains/legacy.test/allocate")
                .exchange().expectStatus().isOk();
        verify(service).allocateNow("legacy.test", null, SUBJECT);
    }

    @Test
    void allocateNow_conflictFromTheService_is409() {
        when(service.allocateNow(anyString(), any(), anyString()))
                .thenReturn(Mono.error(ApiException.conflict("nothing to allocate")));
        asSuperadmin().post().uri("/bff/admin/domains/legacy.test/allocate")
                .exchange().expectStatus().isEqualTo(409);
    }

    @Test
    void allocateNow_asAdmin_isForbidden_andNeverAllocates() {
        asAdmin().post().uri("/bff/admin/domains/legacy.test/allocate")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).allocateNow(anyString(), any(), anyString());
    }

    @Test
    void allocateNow_asUser_isForbidden_andNeverAllocates() {
        asUser().post().uri("/bff/admin/domains/legacy.test/allocate")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).allocateNow(anyString(), any(), anyString());
    }

    @Test
    void responses_carryTheDecision87eFields() {
        when(service.list()).thenReturn(Flux.just(new DomainRegistration("dom-3", "b.test", "b",
                "B", null, "b", null, null, true, Instant.now(), SUBJECT, Instant.now(), false, false,
                0L, DomainIdp.OWN, "s0:c256", "s0:c257", "Brand B", "https://hs.b.test")));
        asSuperadmin().get().uri("/bff/admin/domains")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].brandTitle").isEqualTo("Brand B")
                .jsonPath("$[0].headscaleUrl").isEqualTo("https://hs.b.test");
    }
}
