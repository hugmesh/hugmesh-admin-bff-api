package systems.hugmesh.adminbff.phone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.web.ApiException;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
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
 * The PUBLIC fe-gateway FLEET-OWNER surface ({@code /bff/admin/phone-fleet/**}) — the security
 * acceptance bar for the ONE {@code /bff/admin/**} path a non-superadmin {@code FLEET_ADMIN}
 * reaches, where {@code physical_owner AND owner_domain} is the SOLE tenancy wall.
 * {@code @WebFluxTest} + the REAL {@link SecurityConfig} so BOTH the coarse
 * {@code /bff/admin/phone-fleet/**} path gate AND the per-method {@code @PreAuthorize} run; the
 * services + step-up gates are mocked so every REFUSAL is proven to happen BEFORE the service.
 *
 * <h3>Domain is genuinely issuer-derived here (not hard-wired)</h3>
 * {@code app.tenancy.issuers} maps {@code https://ca -> doma} and {@code https://cb -> domb}, so a
 * mock JWT's validated {@code iss} resolves to a REAL, VARYING {@link
 * systems.hugmesh.commons.security.PrincipalDomain}. That lets the cross-DOMAIN tests use the
 * SAME owner subject on a different issuer and prove the wall keys on BOTH predicates — a bug that
 * dropped the domain (hard-wired {@code "default"}) would forward the wrong scope and be caught by
 * the captor assertions.
 *
 * <ul>
 *   <li>an entitled FLEET_ADMIN's read/list forwards EXACTLY its own subject + issuer-domain to
 *       the scoped service (captor-pinned);</li>
 *   <li>a device owned by ANOTHER owner, OR the same owner in ANOTHER domain, is a uniform 404
 *       (NOT 403 — no enumeration), proving BOTH predicates;</li>
 *   <li>lock/unlock of a cross-owner/cross-domain device → 404; of an owned BYOD device → 409;</li>
 *   <li>an UN-entitled FLEET_ADMIN → 403 "fleet entitlement required" on EVERY endpoint, the
 *       scoped service NEVER reached;</li>
 *   <li>a SUPERADMIN is UNSCOPED (uses the unscoped service) AND entitlement-EXEMPT (isEntitled
 *       never consulted);</li>
 *   <li>a plain ADMIN is admitted at the coarse gate but STILL scoped + entitlement-gated (only
 *       SUPERADMIN is exempt);</li>
 *   <li>USER / MOD → 403 (coarse gate); unauthenticated → 401;</li>
 *   <li>missing/invalid step-up → 403 BEFORE any mutation (and before the entitlement query);</li>
 *   <li>a reflection guard pins {@code @PreAuthorize} on every mapping method of BOTH this
 *       controller AND {@link FleetEntitlementSuperadminController}.</li>
 * </ul>
 */
@WebFluxTest(controllers = PhoneFleetOwnerController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
@TestPropertySource(properties = "app.tenancy.issuers=https://ca=doma,https://cb=domb")
class PhoneFleetOwnerControllerTest {

    private static final String STEP_UP = PhoneLockStepUpGate.STEP_UP_HEADER;
    private static final String TOKEN = "good-token";
    private static final String BASE = "/bff/admin/phone-fleet";

    /** issuer -> domain, via app.tenancy.issuers above. */
    private static final String ISS_A = "https://ca";   // -> doma
    private static final String DOM_A = "doma";
    private static final String ISS_B = "https://cb";   // -> domb
    private static final String DOM_B = "domb";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @MockitoBean PhoneDeviceService phones;
    @MockitoBean PhoneManagementService management;
    @MockitoBean FleetEntitlementService entitlements;
    @MockitoBean PhoneLockStepUpGate stepUp;
    @MockitoBean systems.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @BeforeEach
    void mfaDarkByDefault() {
        // MFA leg ships DARK: no fresh stamp -> only the workload step-up token leg satisfies.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
    }

    private static PhoneDevice phone(String deviceId, String owner, String domain,
                                     String mode, String lockState) {
        return new PhoneDevice("pd-" + deviceId, deviceId, "phone", null, "oriole", null, null,
                null, null, null, null, "phone-host", null, null, false, null, null, false, null,
                null, null, null, null, null, null, null, null, Instant.now(), Instant.now(),
                1L, mode, lockState, "degraded", 1L, "r", "sa", Instant.now(), owner, domain,
                "headwind", null);
    }

    private WebTestClient asFleetAdmin(String subject, String issuer) {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.subject(subject).issuer(issuer))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_FLEET_ADMIN")));
    }

    private WebTestClient asAdmin(String subject, String issuer) {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.subject(subject).issuer(issuer))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asSuperadmin(String subject, String issuer) {
        return web.mutateWith(mockJwt()
                .jwt(j -> j.subject(subject).issuer(issuer))
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

    // ── list: only own owner+domain scope forwarded, keyed on the CALLER's subject ───
    @Test
    void fleetAdmin_list_forwardsOwnSubjectScope_seesOnlyOwnFleet() {
        when(entitlements.isEntitled("owner-a")).thenReturn(Mono.just(true));
        // Two owners' fleets exist; the controller must query ONLY the caller's.
        when(phones.listOwned("owner-a", DOM_A))
                .thenReturn(Flux.just(phone("dev-a", "owner-a", DOM_A, "mesh_owned", "unlocked")));
        when(phones.listOwned("owner-b", DOM_A))
                .thenReturn(Flux.just(phone("dev-b", "owner-b", DOM_A, "mesh_owned", "unlocked")));

        asFleetAdmin("owner-a", ISS_A).get().uri(BASE)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.phones.length()").isEqualTo(1)
                .jsonPath("$.phones[0].deviceId").isEqualTo("dev-a");

        // The scoped query was keyed on the caller's OWN subject + issuer-domain — never owner-b.
        verify(phones).listOwned("owner-a", DOM_A);
        verify(phones, never()).listOwned("owner-b", DOM_A);
        verify(phones, never()).list();
        verify(entitlements).isEntitled("owner-a");
    }

    /**
     * The domain half of the wall is ISSUER-derived, not owner-derived: the SAME subject on a
     * DIFFERENT issuer forwards a DIFFERENT domain. A hard-wired domain would be caught here.
     */
    @Test
    void fleetAdmin_list_domainTracksTheValidatedIssuer_notTheSubject() {
        when(entitlements.isEntitled("owner-a")).thenReturn(Mono.just(true));
        when(phones.listOwned(eq("owner-a"), anyString())).thenReturn(Flux.empty());

        asFleetAdmin("owner-a", ISS_B).get().uri(BASE).exchange().expectStatus().isOk();

        ArgumentCaptor<String> owner = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domain = ArgumentCaptor.forClass(String.class);
        verify(phones).listOwned(owner.capture(), domain.capture());
        assertThat(owner.getValue()).isEqualTo("owner-a");
        assertThat(domain.getValue()).isEqualTo(DOM_B);   // issuer cb -> domb, NOT doma
    }

    // ── get one: 404 (not 403) for a cross-owner device — no enumeration ─────────────
    @Test
    void fleetAdmin_get_ownDevice_ok_butCrossOwnerIs404NotForbidden() {
        when(entitlements.isEntitled(anyString())).thenReturn(Mono.just(true));
        when(phones.findOwned(any(), any(), any())).thenReturn(Mono.empty());
        when(phones.findOwned("dev-x", "owner-a", DOM_A))
                .thenReturn(Mono.just(phone("dev-x", "owner-a", DOM_A, "mesh_owned", "unlocked")));

        asFleetAdmin("owner-a", ISS_A).get().uri(BASE + "/dev-x")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.deviceId").isEqualTo("dev-x");

        // Another owner requesting the very same device id -> 404, never 403 (existence hidden).
        asFleetAdmin("owner-b", ISS_A).get().uri(BASE + "/dev-x")
                .exchange().expectStatus().isNotFound();
        verify(phones).findOwned("dev-x", "owner-b", DOM_A);   // the query WAS owner-scoped
    }

    /**
     * BOTH predicates matter: the SAME owner subject, on a DIFFERENT domain (issuer cb), must NOT
     * see a device it owns in doma — a clean 404 (proves the owner_domain predicate, not just
     * physical_owner). This is the cross-domain leak guard.
     */
    @Test
    void fleetAdmin_get_sameOwner_otherDomain_is404() {
        when(entitlements.isEntitled("owner-a")).thenReturn(Mono.just(true));
        when(phones.findOwned(any(), any(), any())).thenReturn(Mono.empty());
        // The device exists ONLY under (owner-a, doma).
        when(phones.findOwned("dev-x", "owner-a", DOM_A))
                .thenReturn(Mono.just(phone("dev-x", "owner-a", DOM_A, "mesh_owned", "unlocked")));

        // owner-a but arriving via issuer cb (domb): the scoped query misses -> 404.
        asFleetAdmin("owner-a", ISS_B).get().uri(BASE + "/dev-x")
                .exchange().expectStatus().isNotFound();
        verify(phones).findOwned("dev-x", "owner-a", DOM_B);
        verify(phones, never()).findOwned("dev-x", "owner-a", DOM_A);
    }

    // ── lock/unlock: owned+managed ok; cross-owner 404; cross-domain 404; BYOD 409 ───
    @Test
    void fleetAdmin_lock_ownedManaged_reachesLockOwned_withOwnScope() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(entitlements.isEntitled("owner-a")).thenReturn(Mono.just(true));
        when(management.lockOwned(eq("dev-x"), any(), any(), eq("owner-a"), eq(DOM_A)))
                .thenReturn(Mono.just(phone("dev-x", "owner-a", DOM_A, "mesh_owned", "locked")));

        asFleetAdmin("owner-a", ISS_A).post().uri(BASE + "/dev-x/lock")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"stolen\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.lockState").isEqualTo("locked");

        verify(management).lockOwned(eq("dev-x"), any(), any(), eq("owner-a"), eq(DOM_A));
    }

    @Test
    void fleetAdmin_lock_viaMfaLeg_noToken_reachesLockOwned_andConsumesStamp() {
        // The REAL production step-up path for a pure FLEET_ADMIN. A fleet customer CANNOT mint a
        // workload token (DesktopStepUpController is ADMIN+SUPERADMIN, WorkloadSuperadminController
        // is SUPERADMIN, both need an ssh-license), so the Casdoor-MFA leg is their ONLY step-up.
        // A fresh MFA stamp + NO X-PhoneLock-StepUp header must reach lockOwned, and the stamp is
        // consumed single-use. This pins that fleet lock/unlock is actually reachable for its
        // intended caller when app.casdoor.mfa.enabled=true (not a superadmin-token-only feature).
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(true));   // fresh MFA; no token presented
        when(entitlements.isEntitled("owner-a")).thenReturn(Mono.just(true));
        when(management.lockOwned(eq("dev-x"), any(), any(), eq("owner-a"), eq(DOM_A)))
                .thenReturn(Mono.just(phone("dev-x", "owner-a", DOM_A, "mesh_owned", "locked")));

        asFleetAdmin("owner-a", ISS_A).post().uri(BASE + "/dev-x/lock")
                .contentType(MediaType.APPLICATION_JSON)            // NB: no STEP_UP header
                .bodyValue("{\"reason\":\"stolen\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.lockState").isEqualTo("locked");

        verify(management).lockOwned(eq("dev-x"), any(), any(), eq("owner-a"), eq(DOM_A));
        verify(mfaStepUp).consume(any());                           // MFA stamp consumed single-use
    }

    @Test
    void fleetAdmin_lock_crossOwner_is404() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(entitlements.isEntitled("owner-b")).thenReturn(Mono.just(true));
        // The scoped CAS matches 0 rows for a device this caller does not own -> service 404.
        when(management.lockOwned(eq("dev-x"), any(), any(), eq("owner-b"), eq(DOM_A)))
                .thenReturn(Mono.error(ApiException.notFound("phone 'dev-x' not found")));

        asFleetAdmin("owner-b", ISS_A).post().uri(BASE + "/dev-x/lock")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isNotFound();
    }

    @Test
    void fleetAdmin_lock_ownedButBYOD_is409() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(entitlements.isEntitled("owner-a")).thenReturn(Mono.just(true));
        when(management.lockOwned(eq("dev-byod"), any(), any(), eq("owner-a"), eq(DOM_A)))
                .thenReturn(Mono.error(ApiException.conflict("phone 'dev-byod' is not a managed device")));

        asFleetAdmin("owner-a", ISS_A).post().uri(BASE + "/dev-byod/lock")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isEqualTo(409);
    }

    @Test
    void fleetAdmin_unlock_sameOwner_otherDomain_is404() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(entitlements.isEntitled("owner-a")).thenReturn(Mono.just(true));
        when(management.unlockOwned(eq("dev-x"), any(), eq("owner-a"), eq(DOM_B)))
                .thenReturn(Mono.error(ApiException.notFound("phone 'dev-x' not found")));

        asFleetAdmin("owner-a", ISS_B).post().uri(BASE + "/dev-x/unlock")
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isNotFound();
        verify(management).unlockOwned(eq("dev-x"), any(), eq("owner-a"), eq(DOM_B));
    }

    // ── the entitlement gate: un-entitled -> 403 on EVERY endpoint, service untouched ─
    @Test
    void unentitledFleetAdmin_forbiddenEverywhere_serviceNeverReached() {
        when(entitlements.isEntitled("owner-a")).thenReturn(Mono.just(false));
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);   // step-up OK: isolate the 403 to entitlement

        asFleetAdmin("owner-a", ISS_A).get().uri(BASE)
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("fleet entitlement required");
        asFleetAdmin("owner-a", ISS_A).get().uri(BASE + "/dev-x")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("fleet entitlement required");
        asFleetAdmin("owner-a", ISS_A).post().uri(BASE + "/dev-x/lock")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("fleet entitlement required");
        asFleetAdmin("owner-a", ISS_A).post().uri(BASE + "/dev-x/unlock")
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("fleet entitlement required");

        verify(phones, never()).listOwned(any(), any());
        verify(phones, never()).findOwned(any(), any(), any());
        verify(management, never()).lockOwned(any(), any(), any(), any(), any());
        verify(management, never()).unlockOwned(any(), any(), any(), any());
    }

    // ── SUPERADMIN: unscoped AND entitlement-exempt ──────────────────────────────────
    @Test
    void superadmin_isUnscoped_andEntitlementExempt() {
        when(phones.list()).thenReturn(Flux.just(
                phone("dev-a", "owner-a", DOM_A, "mesh_owned", "unlocked"),
                phone("dev-b", "owner-b", DOM_B, "mesh_owned", "locked")));

        asSuperadmin("sa", ISS_A).get().uri(BASE)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.phones.length()").isEqualTo(2);

        // The unscoped read was used; the owner-scoped query + the entitlement gate were NOT.
        verify(phones).list();
        verify(phones, never()).listOwned(any(), any());
        verify(entitlements, never()).isEntitled(any());
    }

    @Test
    void superadmin_lock_usesUnscopedLock_notScoped() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(management.lock(eq("dev-x"), any(), any()))
                .thenReturn(Mono.just(phone("dev-x", "owner-a", DOM_A, "mesh_owned", "locked")));

        asSuperadmin("sa", ISS_A).post().uri(BASE + "/dev-x/lock")
                .header(STEP_UP, TOKEN).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isOk();

        verify(management).lock(eq("dev-x"), any(), any());
        verify(management, never()).lockOwned(any(), any(), any(), any(), any());
        verify(entitlements, never()).isEntitled(any());
    }

    // ── plain ADMIN is admitted at the coarse gate but STILL scoped + entitlement-gated ──
    @Test
    void plainAdmin_isScopedAndEntitlementGated_notExempt() {
        when(entitlements.isEntitled("admin-1")).thenReturn(Mono.just(true));
        when(phones.listOwned("admin-1", DOM_A))
                .thenReturn(Flux.just(phone("dev-a", "admin-1", DOM_A, "mesh_owned", "unlocked")));

        asAdmin("admin-1", ISS_A).get().uri(BASE).exchange().expectStatus().isOk();

        // An ADMIN is NOT the superadmin bypass: it went through the entitlement gate + scope.
        verify(entitlements).isEntitled("admin-1");
        verify(phones).listOwned("admin-1", DOM_A);
        verify(phones, never()).list();
    }

    // ── coarse role gate + auth ──────────────────────────────────────────────────────
    @Test
    void userAndMod_forbidden_atCoarseGate_serviceNeverReached() {
        asUser().get().uri(BASE).exchange().expectStatus().isForbidden();
        asMod().get().uri(BASE).exchange().expectStatus().isForbidden();
        verify(phones, never()).list();
        verify(phones, never()).listOwned(any(), any());
        verify(entitlements, never()).isEntitled(any());
    }

    @Test
    void unauthenticated_is401() {
        web.get().uri(BASE).exchange().expectStatus().isUnauthorized();
        verify(phones, never()).listOwned(any(), any());
    }

    // ── step-up precedes the mutation AND the entitlement query ───────────────────────
    @Test
    void lock_missingStepUp_mfaDark_403_beforeMutationAndEntitlement() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);   // no token, MFA dark
        when(entitlements.isEntitled(anyString())).thenReturn(Mono.just(true));

        asFleetAdmin("owner-a", ISS_A).post().uri(BASE + "/dev-x/lock")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").value(v ->
                        assertThat((String) v).contains("step-up"));

        verify(management, never()).lockOwned(any(), any(), any(), any(), any());
        // Step-up is checked BEFORE the owner scope resolves, so the entitlement query never runs.
        verify(entitlements, never()).isEntitled(any());
    }

    @Test
    void unlock_invalidStepUp_403_serviceNeverReached() {
        when(stepUp.isSatisfied(any(), eq("bad"))).thenReturn(false);
        when(entitlements.isEntitled(anyString())).thenReturn(Mono.just(true));

        asFleetAdmin("owner-a", ISS_A).post().uri(BASE + "/dev-x/unlock")
                .header(STEP_UP, "bad")
                .exchange().expectStatus().isForbidden();
        verify(management, never()).unlockOwned(any(), any(), any(), any());
    }

    // ── reflection guard: @PreAuthorize on EVERY mapping method of BOTH controllers ───
    @Test
    void everyMappingMethod_ofBothFleetControllers_carriesPreAuthorize() {
        assertEveryMappingMethodPreAuthorized(PhoneFleetOwnerController.class,
                "hasAnyRole('FLEET_ADMIN','ADMIN','SUPERADMIN')");
        assertEveryMappingMethodPreAuthorized(FleetEntitlementSuperadminController.class,
                "hasRole('SUPERADMIN')");
    }

    private static final Class<?>[] MAPPING_ANNOTATIONS = {
            GetMapping.class, PostMapping.class, PutMapping.class,
            DeleteMapping.class, RequestMapping.class};

    private static void assertEveryMappingMethodPreAuthorized(Class<?> controller, String expected) {
        int mappings = 0;
        for (Method m : controller.getDeclaredMethods()) {
            boolean isMapping = false;
            for (Class<?> a : MAPPING_ANNOTATIONS) {
                if (m.isAnnotationPresent(a.asSubclass(Annotation.class))) {
                    isMapping = true;
                    break;
                }
            }
            if (!isMapping) {
                continue;
            }
            mappings++;
            var pa = m.getAnnotation(org.springframework.security.access.prepost.PreAuthorize.class);
            assertThat(pa)
                    .as("%s#%s must carry @PreAuthorize (public tenancy-walled surface)",
                            controller.getSimpleName(), m.getName())
                    .isNotNull();
            assertThat(pa.value())
                    .as("%s#%s must require %s", controller.getSimpleName(), m.getName(), expected)
                    .isEqualTo(expected);
        }
        // Guard the guard: a controller with zero detected mappings would vacuously pass.
        assertThat(mappings)
                .as("%s must expose at least one mapping method", controller.getSimpleName())
                .isGreaterThan(0);
    }
}
