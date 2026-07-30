package systems.hugmesh.adminbff.phone;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.adminbff.support.AdminBffPostgresTestSupport;
import systems.hugmesh.adminbff.testsupport.TestIssuer;
import systems.hugmesh.authcore.casdoor.MfaStepUpService;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static reactor.core.publisher.Mono.just;

/**
 * FULL-LIFECYCLE PHONE-FLEET E2E — the missing end-to-end net over the wave-1 fleet-entitlement
 * tenancy wall (changesets 304/305/306) AND the wave-2 Azure-MDM provider telemetry (307). Every
 * existing phone test is a SLICE ({@code @WebFluxTest} controllers with their neighbours mocked,
 * or {@code @DataR2dbcTest} repositories with no HTTP): none drives the REAL wiring
 * end-to-end. This boots the WHOLE {@code AdminBffApplication} on a RANDOM_PORT against a REAL
 * Testcontainers Postgres ({@link AdminBffPostgresTestSupport}) and walks one fleet through its
 * whole life over the ACTUAL HTTP surface with {@link WebTestClient}:
 *
 * <ul>
 *   <li>the REAL {@link systems.hugmesh.adminbff.config.SecurityConfig} filter chain (coarse
 *       path gate + per-method {@code @PreAuthorize}), validating REAL RS256 JWTs minted by an
 *       in-process {@link TestIssuer} per brand — so the {@code physical_owner AND owner_domain}
 *       tenancy wall keys on a genuinely issuer-DERIVED {@link
 *       systems.hugmesh.commons.security.PrincipalDomain}, not a hard-wired string;</li>
 *   <li>the REAL {@link PhoneIngestController} (mTLS-shaped, no JWT), {@link
 *       PhoneManagementSuperadminController}, {@link FleetEntitlementSuperadminController} and the
 *       public {@link PhoneFleetOwnerController};</li>
 *   <li>the REAL {@link PhoneManagementService} + {@link PhoneDeviceService} + repositories +
 *       {@link DefaultPhoneLockEnforcer} with the DEFAULT no-op legs (both DPC families +
 *       mesh-deny off) so enforcement degrades exactly as it ships.</li>
 * </ul>
 *
 * <p><b>Mocked: ONLY the external re-auth edges</b> — {@link PhoneLockStepUpGate} and {@link
 * MfaStepUpService}. The step-up re-confirmation itself is not the feature under test (its own
 * slice tests cover it); mocking it lets the lifecycle drive lock/unlock without minting a live
 * MFA stamp / workload token, while the tenancy wall, the entitlement gate, the CAS state machine
 * and the enforcer all run for real. The JWT decoder is NOT mocked — real signed tokens exercise
 * the production resource server.
 *
 * <p><b>This is an e2e, not a slice: every step asserts BOTH the HTTP response AND the re-read DB
 * row.</b> A gate that fail-opened (dropped a predicate, skipped the entitlement query, mislabelled
 * a BYOD lock) would land a row the DB re-read then catches; a controller that echoed an in-memory
 * value instead of the stored row would pass the HTTP check but fail the DB re-read. Deterministic
 * — no sleeps, monotonic generations asserted by value.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient(timeout = "PT30S")
@ActiveProfiles("test")
@Import(PhoneFleetLifecycleE2eTest.ExcludeTestProbeControllers.class)
class PhoneFleetLifecycleE2eTest extends AdminBffPostgresTestSupport {

    /**
     * Removes the two TOP-LEVEL package-private {@code @RestController} probe stand-ins
     * ({@code Probes} / {@code Guarded} in the {@code config} test sources) that component
     * scanning sweeps into a full-context boot — they collide with the real controllers and fail
     * handler-mapping init with an "Ambiguous mapping". Mirrors the identical helper in {@code
     * RawApiDenyMatrixTest} / {@code OpenApiSpecDumpTest} (copied because those are package-private
     * to other test packages).
     */
    static class ExcludeTestProbeControllers implements BeanDefinitionRegistryPostProcessor {
        private static final java.util.Set<String> TEST_PROBE_TYPES = java.util.Set.of(
                "systems.hugmesh.adminbff.config.Probes",
                "systems.hugmesh.adminbff.config.Guarded");

        @Override
        public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
            for (String name : registry.getBeanDefinitionNames()) {
                String beanClass = registry.getBeanDefinition(name).getBeanClassName();
                if (beanClass != null && TEST_PROBE_TYPES.contains(beanClass)) {
                    registry.removeBeanDefinition(name);
                }
            }
        }
    }

    // ── two brands: brandA -> doma (the fleet under test), brandB -> domb (cross-domain) ──
    private static TestIssuer brandA;
    private static TestIssuer brandB;

    private static final String OWNER_A = "owner-a";
    private static final String OWNER_B = "owner-b";
    private static final String DOM_A = "doma";
    private static final String DOM_B = "domb";

    private static final String INGEST = "/bff/internal/device-registry/phone-ingest";
    private static final String SUPER = "/bff/superadmin/phone-devices";
    private static final String ENTITLE = "/bff/superadmin/fleet-entitlements";
    private static final String FLEET = "/bff/admin/phone-fleet";

    @BeforeAll
    static void issuers() {
        brandA = new TestIssuer();
        brandB = new TestIssuer();
    }

    @AfterAll
    static void stop() {
        if (brandA != null) brandA.close();
        if (brandB != null) brandB.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        // Two trusted brands => multi-issuer mode: the prod SecurityConfig swaps to the
        // TenancyResourceServerConfig per-issuer resolver, and PrincipalDomain derives doma/domb
        // from the validated issuer. A hard-wired-domain bug would be caught by the cross-domain
        // 404 leg below.
        r.add("app.tenancy.issuers",
                () -> brandA.issuerUri() + "=" + DOM_A + "," + brandB.issuerUri() + "=" + DOM_B);
        // Neutralise the autoconfigured single-issuer decoder so boot never dials a real Casdoor.
        r.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> "");
        r.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri", () -> "http://127.0.0.1:0/jwks");
    }

    @Autowired WebTestClient web;
    @Autowired PhoneDeviceRepository phones;     // real facade — the DB re-read source of truth
    @Autowired DatabaseClient db;

    // The ONLY mocks: the external re-auth edges (not the feature under test).
    @MockitoBean PhoneLockStepUpGate stepUp;
    @MockitoBean MfaStepUpService mfaStepUp;

    @BeforeEach
    void reset() {
        db.sql("DELETE FROM phone_device").fetch().rowsUpdated().block();
        db.sql("DELETE FROM fleet_entitlement").fetch().rowsUpdated().block();
        // Step-up satisfied for every mutation (the MFA leg re-auth is mocked). isFresh/consume
        // are stubbed so the controller's session-token plumbing runs; isSatisfied returns true so
        // a 403 can only come from the entitlement gate / role gate, never step-up.
        when(mfaStepUp.isFresh(any())).thenReturn(just(true));
        when(mfaStepUp.consume(any())).thenReturn(reactor.core.publisher.Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean())).thenReturn(true);
    }

    // ── token mints ──────────────────────────────────────────────────────────────
    private static String superadmin()        { return brandA.mint("super-op", List.of("superadmin")); }
    private static String fleetAdminA()        { return brandA.mint(OWNER_A, List.of("fleet_admin")); }
    private static String fleetAdminA_domB()   { return brandB.mint(OWNER_A, List.of("fleet_admin")); }

    // ── ingest bodies (mTLS-shaped, no JWT) ────────────────────────────────────────
    private static String ingestBody(String deviceId, String provider, String intuneId) {
        StringBuilder b = new StringBuilder()
                .append("{\"schema\":\"phone-ingest/v2\",\"device_id\":\"").append(deviceId)
                .append("\",\"device_class\":\"phone\",\"codename\":\"oriole\",\"os\":\"GrapheneOS\"");
        if (provider != null) {
            b.append(",\"mdm_provider\":\"").append(provider).append('"');
        }
        if (intuneId != null) {
            b.append(",\"intune_device_id\":\"").append(intuneId).append('"');
        }
        return b.append('}').toString();
    }

    private void ingest(String deviceId, String provider, String intuneId) {
        web.post().uri(INGEST).contentType(MediaType.APPLICATION_JSON)
                .bodyValue(ingestBody(deviceId, provider, intuneId))
                .exchange().expectStatus().isOk();
    }

    // ── superadmin provisioning helpers (real /bff/superadmin/** endpoints) ────────
    private void assignOwner(String deviceId, String owner, String domain) {
        web.put().uri(SUPER + "/" + deviceId + "/owner")
                .header("Authorization", "Bearer " + superadmin())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"physicalOwner\":\"" + owner + "\",\"ownerDomain\":\"" + domain + "\"}")
                .exchange().expectStatus().isOk();
    }

    private void markManaged(String deviceId) {
        web.put().uri(SUPER + "/" + deviceId + "/management")
                .header("Authorization", "Bearer " + superadmin())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"mode\":\"mesh_owned\"}")
                .exchange().expectStatus().isOk();
    }

    private void grantEntitlement(String subject) {
        web.put().uri(ENTITLE + "/" + subject)
                .header("Authorization", "Bearer " + superadmin())
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange().expectStatus().isOk();
    }

    private void revokeEntitlement(String subject) {
        web.delete().uri(ENTITLE + "/" + subject)
                .header("Authorization", "Bearer " + superadmin())
                .exchange().expectStatus().isOk();
    }

    private PhoneDevice dbRow(String deviceId) {
        return phones.findByDeviceId(deviceId).block();
    }

    /**
     * The whole fleet lifecycle in one deterministic walk (shared sequential state is exactly
     * what an e2e should exercise): ingest -> provision -> entitle -> scoped reads -> lock/unlock
     * -> azure provider-independence -> entitlement revocation, asserting the HTTP surface AND the
     * re-read DB row at every step.
     */
    @Test
    void fullFleetLifecycle_overRealWiring() {
        // ── (a) ingest four managed/BYOD phones across two owners + two providers ──────
        ingest("dev-a1", "headwind", null);        // owner-a, will be managed (headwind)
        ingest("dev-b1", "headwind", null);        // owner-b, will be managed
        ingest("dev-byod", "headwind", null);      // owner-a, stays UNMANAGED (BYOD)
        ingest("dev-azure", "azure-intune", "intune-dev-42");  // owner-a, azure-intune, managed

        // The device-reported provider (307) round-tripped through the ingest channel...
        assertThat(dbRow("dev-a1").effectiveMdmProvider()).isEqualTo("headwind");
        assertThat(dbRow("dev-azure").mdmProvider()).isEqualTo("azure-intune");
        assertThat(dbRow("dev-azure").intuneDeviceId()).isEqualTo("intune-dev-42");
        // ...but the ingest channel wrote NO operator state (the wave-1 trust boundary).
        assertThat(dbRow("dev-a1").physicalOwner()).isNull();
        assertThat(dbRow("dev-a1").isManaged()).isFalse();

        // ── (b) SUPERADMIN provisions owners + managed status via the real endpoints ───
        assignOwner("dev-a1", OWNER_A, DOM_A);
        assignOwner("dev-b1", OWNER_B, DOM_A);
        assignOwner("dev-byod", OWNER_A, DOM_A);
        assignOwner("dev-azure", OWNER_A, DOM_A);
        markManaged("dev-a1");
        markManaged("dev-b1");
        markManaged("dev-azure");
        // dev-byod deliberately left unmanaged.
        assertThat(dbRow("dev-a1").physicalOwner()).isEqualTo(OWNER_A);
        assertThat(dbRow("dev-a1").ownerDomain()).isEqualTo(DOM_A);
        assertThat(dbRow("dev-a1").isManaged()).isTrue();
        assertThat(dbRow("dev-byod").isManaged()).isFalse();

        // grant owner-a its fleet entitlement via the real /bff/superadmin endpoint.
        grantEntitlement(OWNER_A);
        assertThat(db.sql("SELECT COUNT(*) c FROM fleet_entitlement WHERE subject = '" + OWNER_A + "'")
                .map((r, m) -> r.get("c", Long.class)).one().block()).isEqualTo(1L);

        // ── (c) a FLEET_ADMIN for owner-a@doma: owner+domain tenancy wall ──────────────
        // list -> sees ONLY its own three devices, never owner-b's.
        web.get().uri(FLEET).header("Authorization", "Bearer " + fleetAdminA())
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.phones.length()").isEqualTo(3)
                .jsonPath("$.phones[?(@.deviceId=='dev-b1')]").doesNotExist();

        // own device -> 200.
        web.get().uri(FLEET + "/dev-a1").header("Authorization", "Bearer " + fleetAdminA())
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.deviceId").isEqualTo("dev-a1");

        // owner-b's device -> 404 (not 403 — no enumeration).
        web.get().uri(FLEET + "/dev-b1").header("Authorization", "Bearer " + fleetAdminA())
                .exchange().expectStatus().isNotFound();

        // own device but a WRONG-DOMAIN JWT (owner-a via brandB=domb) -> 404 (proves the
        // owner_domain half of the wall; a hard-wired domain would 200 here).
        web.get().uri(FLEET + "/dev-a1").header("Authorization", "Bearer " + fleetAdminA_domB())
                .exchange().expectStatus().isNotFound();

        // ── (d) lock/unlock own managed; BYOD 409; monotonic generation ────────────────
        assertThat(dbRow("dev-a1").lockGeneration()).isEqualTo(0L);
        web.post().uri(FLEET + "/dev-a1/lock").header("Authorization", "Bearer " + fleetAdminA())
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"stolen\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.lockState").isEqualTo("locked");
        PhoneDevice lockedA1 = dbRow("dev-a1");
        assertThat(lockedA1.lockState()).isEqualTo("locked");
        assertThat(lockedA1.lockGeneration()).isEqualTo(1L);          // bumped
        assertThat(lockedA1.lockReason()).isEqualTo("stolen");

        // locking the OWNED BYOD device -> 409, DB unchanged.
        web.post().uri(FLEET + "/dev-byod/lock").header("Authorization", "Bearer " + fleetAdminA())
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isEqualTo(409);
        PhoneDevice byod = dbRow("dev-byod");
        assertThat(byod.lockState()).isEqualTo("unlocked");
        assertThat(byod.lockGeneration()).isEqualTo(0L);

        // unlock own device -> 200, generation MONOTONIC across lock AND unlock (2).
        web.post().uri(FLEET + "/dev-a1/unlock").header("Authorization", "Bearer " + fleetAdminA())
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.lockState").isEqualTo("unlocked");
        PhoneDevice unlockedA1 = dbRow("dev-a1");
        assertThat(unlockedA1.lockState()).isEqualTo("unlocked");
        assertThat(unlockedA1.lockGeneration()).isEqualTo(2L);        // monotonic across unlock too

        // ── (e) the azure-intune device: lifecycle is provider-INDEPENDENT at the control ─
        //        plane. Lock lands (200) and the row is authoritatively locked; enforcement
        //        DEGRADES (all legs off) — proving provider is telemetry, not a gate.
        web.post().uri(FLEET + "/dev-azure/lock").header("Authorization", "Bearer " + fleetAdminA())
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"lost\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.lockState").isEqualTo("locked");
        PhoneDevice azure = dbRow("dev-azure");
        assertThat(azure.mdmProvider()).isEqualTo("azure-intune");   // telemetry survives the lock
        assertThat(azure.lockState()).isEqualTo("locked");           // control-plane lock authoritative
        assertThat(azure.lockGeneration()).isEqualTo(1L);
        assertThat(azure.lockPropagationState()).isEqualTo("degraded");  // legs off -> degraded, not failed

        // ── (f) revoke owner-a's entitlement -> 403 EVERYWHERE, DB untouched ───────────
        revokeEntitlement(OWNER_A);
        long a1GenBefore = dbRow("dev-a1").lockGeneration();

        web.get().uri(FLEET).header("Authorization", "Bearer " + fleetAdminA())
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("fleet entitlement required");
        web.get().uri(FLEET + "/dev-a1").header("Authorization", "Bearer " + fleetAdminA())
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("fleet entitlement required");
        web.post().uri(FLEET + "/dev-a1/lock").header("Authorization", "Bearer " + fleetAdminA())
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("fleet entitlement required");
        web.post().uri(FLEET + "/dev-a1/unlock").header("Authorization", "Bearer " + fleetAdminA())
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("fleet entitlement required");

        // No un-entitled request mutated anything.
        assertThat(dbRow("dev-a1").lockGeneration()).isEqualTo(a1GenBefore);
        assertThat(dbRow("dev-a1").lockState()).isEqualTo("unlocked");
    }

    /**
     * The SUPERADMIN plane stays UNSCOPED + entitlement-EXEMPT even with no entitlement row: a
     * superadmin lists the WHOLE fleet (both owners, both domains) and locks a device it does not
     * own — over the same public {@code /bff/admin/phone-fleet/**} surface. This pins that the
     * genuine super-role authority is the bypass, distinct from the owner-scoped fleet-admin path.
     */
    @Test
    void superadmin_isUnscopedAndEntitlementExempt_overThePublicSurface() {
        ingest("dev-sa-a", "headwind", null);
        ingest("dev-sa-b", "azure-intune", "intune-sa-1");
        assignOwner("dev-sa-a", OWNER_A, DOM_A);
        assignOwner("dev-sa-b", OWNER_B, DOM_B);
        markManaged("dev-sa-a");
        markManaged("dev-sa-b");
        // deliberately NO entitlement granted for the superadmin subject.

        web.get().uri(FLEET).header("Authorization", "Bearer " + superadmin())
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.phones.length()").isEqualTo(2);   // whole fleet, unscoped

        // locks a device owned by owner-b in domb, which no fleet-admin from doma could touch.
        web.post().uri(FLEET + "/dev-sa-b/lock").header("Authorization", "Bearer " + superadmin())
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"ops\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.lockState").isEqualTo("locked");
        assertThat(dbRow("dev-sa-b").lockState()).isEqualTo("locked");
    }
}
