package net.hugmesh.adminbff.optionalservices;

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
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The acceptance bar for {@code /bff/superadmin/optional-services} — the SUPERADMIN control
 * surface that lets an image shipped with a subset of services have others turned on later.
 * Mirrors {@code GamesCatalogSuperadminControllerTest}: {@code @WebFluxTest} + the REAL
 * {@link SecurityConfig}, so BOTH the coarse {@code /bff/superadmin/**} path gate AND the
 * per-method {@code @PreAuthorize("hasRole('SUPERADMIN')")} actually run.
 *
 * <p>Unlike that test this one imports the REAL {@link OptionalServiceAdminService} and
 * {@link OptionalServiceRegistry} and mocks only the CLUSTER seam
 * ({@link OptionalServiceClient}). The refusal ladder lives in the service, and a refusal that
 * is only unit-tested below the controller proves nothing about what a superadmin's HTTP call
 * does — so it is asserted here, at the wire.
 *
 * <p>The registry is a {@link MockitoSpyBean}: every test sees the REAL registry unless it
 * stubs one call. Two tests do, because since #106 no real slug reaches their branch — no
 * managed slug lacks its apps/16 pointer (so nothing carries the selfHeal warning) and no slug
 * is {@code NOT_IN_CRD_ENUM}. Both branches are still live code the next upstream slug can
 * land in, so each is driven through the wire with a stubbed registry answer, and says so.
 *
 * <ul>
 *   <li><b>authz</b> — SUPERADMIN allowed; ADMIN / MOD / USER 403 on BOTH verbs and NEVER reach
 *       the cluster seam; anonymous 401.</li>
 *   <li><b>catalogue</b> — lists managed AND not-toggleable slugs, each with its named reason;
 *       {@code character-forge} and {@code meshbridge} (the two silently-inert toggles this
 *       surface was built against) appear as TOGGLEABLE with NO warnings.</li>
 *   <li><b>refusal</b> — {@code workloadConsole} (no 13a element) and a stubbed
 *       {@code NOT_IN_CRD_ENUM} slug are 422 with the named reason and NO write attempted; an
 *       unknown slug is 404 with no write; a dark reconciler is 503 {@code dark:true} with no
 *       write.</li>
 * </ul>
 */
@WebFluxTest(controllers = OptionalServiceSuperadminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class, OptionalServiceAdminService.class, OptionalServiceRegistry.class})
class OptionalServiceSuperadminControllerTest {

    private static final String PATH = "/bff/superadmin/optional-services";
    private static final String SUBJECT = "superadmin-subject-7";
    private static final String ON = "{\"enabled\":true,\"reason\":\"operator asked for it\"}";

    @Autowired ApplicationContext context;

    @MockitoBean OptionalServiceClient client;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoSpyBean OptionalServiceRegistry registry;

    WebTestClient web;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        // Default: a REAL cluster client with no CRs yet (the interesting refusals are about the
        // registry, not about the CR list).
        when(client.isReal()).thenReturn(true);
        when(client.listDesired()).thenReturn(List.of());
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

    private static OptionalServiceCr cr(String slug, boolean enabled) {
        return new OptionalServiceCr(slug, "devops", slug, enabled, "operator asked for it",
                SUBJECT, 2L, "77");
    }

    // ── authorization: the role floor ───────────────────────────────────────────────

    @Test
    void catalogue_asSuperadmin_isAllowed() {
        asSuperadmin().get().uri(PATH).exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.reconcilerEnabled").isEqualTo(true);
    }

    @Test
    void catalogue_asAdminModUser_isForbidden_andNeverReachesTheCluster() {
        asAdmin().get().uri(PATH).exchange().expectStatus().isForbidden();
        asMod().get().uri(PATH).exchange().expectStatus().isForbidden();
        asUser().get().uri(PATH).exchange().expectStatus().isForbidden();
        verify(client, never()).listDesired();
    }

    @Test
    void catalogue_anonymous_isUnauthorized() {
        web.get().uri(PATH).exchange().expectStatus().isUnauthorized();
        verify(client, never()).listDesired();
    }

    @Test
    void setEnabled_asAdminModUser_isForbidden_andNeverWrites() {
        for (WebTestClient c : List.of(asAdmin(), asMod(), asUser())) {
            c.put().uri(PATH + "/akkoma").contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                    .exchange().expectStatus().isForbidden();
        }
        verify(client, never()).setEnabled(anyString(), anyBoolean(), any(), any());
    }

    @Test
    void setEnabled_anonymous_isUnauthorized_andNeverWrites() {
        web.put().uri(PATH + "/akkoma").contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                .exchange().expectStatus().isUnauthorized();
        verify(client, never()).setEnabled(anyString(), anyBoolean(), any(), any());
    }

    // ── the catalogue reports TOGGLEABILITY, not just membership ────────────────────

    @Test
    void catalogue_reportsManagedAndNotToggleableSlugs_withNamedReasons() {
        asSuperadmin().get().uri(PATH).exchange()
                .expectStatus().isOk()
                .expectBody()
                // the fixed defect: character-forge is listed AND actually toggleable, and
                // (#106) no longer warns about a selfHeal revert apps/16 now prevents
                .jsonPath("$.services[?(@.slug=='character-forge')].toggleable").isEqualTo(true)
                .jsonPath("$.services[?(@.slug=='character-forge')].warnings[0]").doesNotExist()
                // #106: meshbridge was refused as NOT_IN_CRD_ENUM while the CRD enum carried
                // it; it is managed now, with a real Application name and no refusal reason
                .jsonPath("$.services[?(@.slug=='meshbridge')].toggleable").isEqualTo(true)
                // (a filter yields a one-element list, so "null" reads as [null])
                .jsonPath("$.services[?(@.slug=='meshbridge')].notToggleableReason")
                .value(org.hamcrest.Matchers.contains(org.hamcrest.Matchers.nullValue()))
                .jsonPath("$.services[?(@.slug=='meshbridge')].applicationName")
                .isEqualTo("optional-meshbridge")
                .jsonPath("$.services[?(@.slug=='meshbridge')].warnings[0]").doesNotExist()
                // workloadConsole has the ConfigMap boolean but no ApplicationSet element
                .jsonPath("$.services[?(@.slug=='workloadConsole')].toggleable").isEqualTo(false)
                .jsonPath("$.services[?(@.slug=='workloadConsole')].notToggleableReason")
                .isEqualTo("NO_APPLICATIONSET_ELEMENT")
                // a plain managed slug carries no warnings and a real application name
                .jsonPath("$.services[?(@.slug=='akkoma')].applicationName")
                .isEqualTo("optional-akkoma")
                // a JsonPath FILTER yields a list-of-matches, so an empty warnings array shows up
                // as [[]] — assert the absence of a first element instead of "isEmpty".
                .jsonPath("$.services[?(@.slug=='akkoma')].warnings[0]").doesNotExist();
    }

    @Test
    void catalogue_joinsLiveCrState() {
        when(client.listDesired()).thenReturn(List.of(cr("akkoma", true)));
        asSuperadmin().get().uri(PATH).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.services[?(@.slug=='akkoma')].enabled").isEqualTo(true)
                .jsonPath("$.services[?(@.slug=='akkoma')].crPresent").isEqualTo(true)
                .jsonPath("$.services[?(@.slug=='akkoma')].requestedBy").isEqualTo(SUBJECT)
                // a managed slug with no CR reads false, and says WHY it reads false
                .jsonPath("$.services[?(@.slug=='tuwunel')].enabled").isEqualTo(false)
                .jsonPath("$.services[?(@.slug=='tuwunel')].crPresent").isEqualTo(false);
    }

    @Test
    void catalogue_whileDark_saysSo_ratherThanLookingHealthy() {
        when(client.isReal()).thenReturn(false);
        asSuperadmin().get().uri(PATH).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.reconcilerEnabled").isEqualTo(false)
                .jsonPath("$.note").value(org.hamcrest.Matchers.containsString("READ-ONLY"));
    }

    // ── the happy write ────────────────────────────────────────────────────────────

    @Test
    void setEnabled_asSuperadmin_writesTheCr_stampingTheJwtSubject() {
        when(client.setEnabled(eq("akkoma"), eq(true), anyString(), eq(SUBJECT)))
                .thenReturn(cr("akkoma", true));

        asSuperadmin().put().uri(PATH + "/akkoma")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.slug").isEqualTo("akkoma")
                .jsonPath("$.enabled").isEqualTo(true)
                .jsonPath("$.requestedBy").isEqualTo(SUBJECT)
                .jsonPath("$.applicationName").isEqualTo("optional-akkoma")
                .jsonPath("$.warnings").isEmpty();

        verify(client).setEnabled("akkoma", true, "operator asked for it", SUBJECT);
    }

    /**
     * #106, half 1: meshbridge used to be answered 422 NOT_IN_CRD_ENUM although the CRD enum
     * carried it. It must now reach the CR write like any managed slug. (The reconciler side —
     * that the CR is actuated and status-written — is pinned by
     * {@code OptionalServiceRegistryParityTest#reconciler_actuatesAndStatusWrites_everyManagedSlug}.)
     */
    @Test
    void setEnabled_meshbridge_writesTheCr_insteadOfRefusing() {
        when(client.setEnabled(eq("meshbridge"), eq(true), anyString(), eq(SUBJECT)))
                .thenReturn(cr("meshbridge", true));

        asSuperadmin().put().uri(PATH + "/meshbridge")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.slug").isEqualTo("meshbridge")
                .jsonPath("$.enabled").isEqualTo(true)
                .jsonPath("$.applicationName").isEqualTo("optional-meshbridge")
                .jsonPath("$.warnings").isEmpty();

        verify(client).setEnabled("meshbridge", true, "operator asked for it", SUBJECT);
    }

    /**
     * #106, half 2: generator apps/16 carries {@code /data/character-forge}, so the toggle
     * response must NOT warn about a selfHeal revert — that warning was a false alarm.
     */
    @Test
    void setEnabled_characterForge_succeeds_withNoFalseSelfHealWarning() {
        when(client.setEnabled(eq("character-forge"), eq(true), any(), eq(SUBJECT)))
                .thenReturn(cr("character-forge", true));

        asSuperadmin().put().uri(PATH + "/character-forge")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.slug").isEqualTo("character-forge")
                .jsonPath("$.warnings").isEmpty();
    }

    /**
     * The partial-actuation warning is still live code, but no real managed slug reaches it
     * since #106 (the parity test pins that set as empty). So the registry answer is STUBBED
     * for one slug — a managed entry apps/16 does not protect — and the wire response must
     * report the gap rather than swallow it. This is a hypothetical registry state, not a
     * claim about akkoma.
     */
    @Test
    void setEnabled_managedSlugWithoutApps16Pointer_carriesThePartialActuationWarning() {
        doReturn(new OptionalServiceRegistry.Entry("akkoma", "hugmesh-backend", "/social/mastodon",
                "Akkoma (Mastodon)", false)).when(registry).entry("akkoma");
        when(client.setEnabled(eq("akkoma"), eq(true), any(), eq(SUBJECT)))
                .thenReturn(cr("akkoma", true));

        asSuperadmin().put().uri(PATH + "/akkoma")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.slug").isEqualTo("akkoma")
                // the apps/16 gap is REPORTED, not swallowed — the whole point of this surface
                .jsonPath("$.warnings[0]")
                .value(org.hamcrest.Matchers.containsString("apps/16"))
                .jsonPath("$.warnings[0]")
                .value(org.hamcrest.Matchers.containsString("selfHeal"));
    }

    // ── the refusal ladder: nothing silently succeeds ───────────────────────────────

    /**
     * No real slug is {@code NOT_IN_CRD_ENUM} since #106 (meshbridge was, falsely), so a
     * hypothetical slug is stubbed into the not-toggleable half with that reason: the next slug
     * that gains a 13a element before its CRD enum value must still be refused by name.
     */
    @Test
    void setEnabled_slugNotInCrdEnum_is422_withTheNamedReason_andNoWrite() {
        doReturn(true).when(registry).isPlatformKnown("next-optional-slug");
        doReturn(OptionalServiceRegistry.NotToggleable.NOT_IN_CRD_ENUM)
                .when(registry).notToggleableReason("next-optional-slug");

        asSuperadmin().put().uri(PATH + "/next-optional-slug")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                .exchange()
                .expectStatus().isEqualTo(422)
                .expectBody()
                .jsonPath("$.error").value(org.hamcrest.Matchers.containsString("NOT_IN_CRD_ENUM"))
                .jsonPath("$.error").value(org.hamcrest.Matchers.containsString("Nothing was written"));

        verify(client, never()).setEnabled(anyString(), anyBoolean(), any(), any());
    }

    @Test
    void setEnabled_slugWithNoApplicationSetElement_is422_andNoWrite() {
        asSuperadmin().put().uri(PATH + "/workloadConsole")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                .exchange()
                .expectStatus().isEqualTo(422)
                .expectBody()
                .jsonPath("$.error")
                .value(org.hamcrest.Matchers.containsString("NO_APPLICATIONSET_ELEMENT"));

        verify(client, never()).setEnabled(anyString(), anyBoolean(), any(), any());
    }

    @Test
    void setEnabled_unknownSlug_is404_andNoWrite() {
        asSuperadmin().put().uri(PATH + "/definitely-not-a-service")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                .exchange()
                .expectStatus().isNotFound()
                .expectBody()
                .jsonPath("$.error")
                .value(org.hamcrest.Matchers.containsString("unknown optional-service slug"));

        verify(client, never()).setEnabled(anyString(), anyBoolean(), any(), any());
    }

    @Test
    void setEnabled_whileDark_is503_dark_andWritesNothing() {
        when(client.isReal()).thenReturn(false);
        when(client.setEnabled(anyString(), anyBoolean(), any(), any()))
                .thenThrow(new OptionalServiceWriteException(
                        OptionalServiceWriteException.Kind.NOT_WIRED, "not wired to a cluster"));

        asSuperadmin().put().uri(PATH + "/akkoma")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody()
                .jsonPath("$.dark").isEqualTo(true)
                .jsonPath("$.note")
                .value(org.hamcrest.Matchers.containsString("NO OptionalService CR was written"));
    }

    @Test
    void setEnabled_apiServerRejection_is422_notASilentSuccess() {
        when(client.setEnabled(anyString(), anyBoolean(), any(), any()))
                .thenThrow(new OptionalServiceWriteException(
                        OptionalServiceWriteException.Kind.REJECTED, "admission webhook denied"));

        asSuperadmin().put().uri(PATH + "/akkoma")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                .exchange()
                .expectStatus().isEqualTo(422)
                .expectBody()
                .jsonPath("$.error")
                .value(org.hamcrest.Matchers.containsString("admission webhook denied"));
    }

    @Test
    void setEnabled_transportFailure_is503_notASilentSuccess() {
        when(client.setEnabled(anyString(), anyBoolean(), any(), any()))
                .thenThrow(new OptionalServiceWriteException(
                        OptionalServiceWriteException.Kind.FAILED, "connection reset"));

        asSuperadmin().put().uri(PATH + "/akkoma")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(ON)
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody()
                .jsonPath("$.error")
                .value(org.hamcrest.Matchers.containsString("connection reset"));
    }

    // ── body validation ────────────────────────────────────────────────────────────

    @Test
    void setEnabled_missingEnabled_is400_andNoWrite() {
        asSuperadmin().put().uri(PATH + "/akkoma")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"why not\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.enabled").exists();

        verify(client, never()).setEnabled(anyString(), anyBoolean(), any(), any());
    }

    @Test
    void setEnabled_overlongReason_is400_beforeTheApiServerWouldRejectIt() {
        String reason = "x".repeat(513);
        asSuperadmin().put().uri(PATH + "/akkoma")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\":true,\"reason\":\"" + reason + "\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.reason").exists();

        verify(client, never()).setEnabled(anyString(), anyBoolean(), any(), any());
    }
}
