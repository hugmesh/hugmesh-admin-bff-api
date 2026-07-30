package systems.hugmesh.adminbff.security;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.adminbff.announcement.AnnouncementRowRepository;
import systems.hugmesh.adminbff.device.DeviceRowRepository;
import systems.hugmesh.adminbff.domainlock.DomainLockRowRepository;
import systems.hugmesh.adminbff.egressvpn.VpnConfigRowRepository;
import systems.hugmesh.adminbff.routeaccess.RouteAccessRowRepository;
import systems.hugmesh.adminbff.suspension.AccessSuspensionRowRepository;
import systems.hugmesh.adminbff.support.AdminBffPostgresTestSupport;
import systems.hugmesh.adminbff.testsupport.TestIssuer;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RAW-API NEGATIVE DENY MATRIX for hugmesh-admin-bff-api — a HTTP-boundary
 * security suite that drives REAL RS256 tokens (minted in-process by two
 * {@link TestIssuer} JWKS servers — arbitrary issuer / roles / sub / domain) through
 * the REAL production {@link systems.hugmesh.adminbff.config.SecurityConfig}
 * filter chain ({@code commonRoutes} path table), the REAL
 * {@code @PreAuthorize} reactive method security, the REAL controllers + services,
 * and a REAL Liquibase-applied Postgres store ({@link AdminBffPostgresTestSupport}). NO production
 * code is touched — this is a purely-additive {@code src/test} coverage add.
 *
 * <p><b>What this proves (the authority for every expected status):</b>
 * <ul>
 *   <li><b>SUPERADMIN-only control plane</b> — {@code POST /bff/superadmin/cloud-backups/total}
 *       ({@code hasRole('SUPERADMIN')} at the {@code /bff/superadmin/**} path table) AND the
 *       SUPERADMIN-only mutations that live UNDER {@code /bff/admin/**} but carry a per-method
 *       {@code @PreAuthorize("hasRole('SUPERADMIN')")} — device-license register/grant/deregister,
 *       egress-vpn import/assign/revoke, domain-registry create — are DENIED (403) to a plain
 *       ADMIN, a MOD, a USER, and a CROSS-DOMAIN ADMIN. The {@code /bff/admin/**} coarse gate
 *       only asserts ROLE_ADMIN, so the SUPERADMIN cut here is the {@code @PreAuthorize} method
 *       gate — exactly the escalation boundary an ADMIN must not cross.</li>
 *   <li><b>ADMIN own-domain actions</b> — suspend ({@code POST /bff/admin/access-roles/...}),
 *       domain-lock ({@code POST /bff/admin/domain-lock/...}), oidc-provider roles
 *       ({@code PUT /bff/admin/oidc-providers/{p}/roles}), route-access
 *       ({@code POST /bff/admin/route-access}) and announcements ({@code POST /bff/admin/announcements})
 *       are DENIED (403) to MOD and USER (the {@code /bff/admin/**} path table requires
 *       ROLE_ADMIN|ROLE_SUPERADMIN; a MOD/USER token carries neither).</li>
 *   <li><b>Token integrity / fail-closed</b> — a FORGED (tampered-signature), a
 *       FOREIGN-ISSUER (well-formed, correctly-signed, but issuer NOT in
 *       {@code app.tenancy.issuers}), and an EXPIRED real-issuer token each get 401 on a
 *       protected surface (the multi-issuer resolver fail-closes: no manager / failed
 *       validation -> 401, never a default-accept).</li>
 * </ul>
 *
 * <p><b>Owner/domain derives from the JWT, never the body.</b> Every cross-domain-admin
 * DENY presents a token whose issuer-derived {@code DOMAIN_<x>} is brand-Y while the
 * request targets brand-X data; the deny does not depend on (and is not defeated by) the
 * body's {@code domain} field.
 *
 * <p><b>MUTATION-RESISTANT (verify-NEVER-WROTE).</b> The services + repositories are REAL
 * and NOT mocked, so a DENY assertion is not circular. After EACH denied mutation we
 * RE-READ the backing table's row count and assert it is UNCHANGED — proving the denied
 * write produced NO side effect. Were any gate to fail-open (drop the {@code @PreAuthorize},
 * widen the path table, or skip issuer/signature/expiry validation), the controller would
 * run, the row would land, and the re-read would FAIL loudly. The status assertion and the
 * row-count re-read are independent witnesses of the same boundary.
 *
 * <p>Wiring follows the federation-api {@code CrossDomainWriteIsolationTest} / the repo's
 * own {@link systems.hugmesh.adminbff.config.MultiIssuerSecuritySliceTest} recipe: real
 * per-brand issuers are supplied via {@link DynamicPropertySource} ({@code app.tenancy.issuers}
 * carries '=' so {@code TenancyResourceServerConfig} activates and the prod resource server
 * swaps to the multi-issuer resolver), and the autoconfigured single-issuer decoder is
 * neutralised (blank issuer-uri + dummy jwk-set-uri) so boot never dials a real Casdoor.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient(timeout = "PT30S")
@ActiveProfiles("test")
// PostgresTestSupport = the Testcontainers Postgres store the repo's full-context tests share.
// ExcludeTestProbeControllers removes the two TOP-LEVEL package-private @RestController
// probe stand-ins (Probes / Guarded in the config test sources) that component-scan would
// otherwise sweep in, colliding with the real controllers (Ambiguous mapping). Reused
// the OpenApiSpecDumpTest pattern so this full-context boot mounts ONLY the production
// surface under test.
@Import(RawApiDenyMatrixTest.ExcludeTestProbeControllers.class)
class RawApiDenyMatrixTest extends AdminBffPostgresTestSupport {

    /**
     * Removes the two TOP-LEVEL package-private {@code @RestController} probe stand-ins
     * ({@code Probes} / {@code Guarded} in the {@code config} test sources) that component
     * scanning sweeps in — they collide with the real controllers (e.g.
     * {@code Probes#admin()} vs {@code AdminController#allowlist()}, both
     * {@code GET /bff/admin/allowlist}) and fail handler-mapping init with an "Ambiguous
     * mapping". Mirrors {@code OpenApiSpecDumpTest.ExcludeTestProbeControllers}; copied here
     * because that one is package-private to a different test package.
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

    // Two trusted brands + one untrusted (foreign) issuer. The foreign issuer is NEVER
    // listed in app.tenancy.issuers, so a token it mints fail-closes to 401.
    private static TestIssuer brandX;
    private static TestIssuer brandY;
    private static TestIssuer foreign;

    @BeforeAll
    static void issuers() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        foreign = new TestIssuer();
    }

    @AfterAll
    static void stop() {
        if (brandX != null) brandX.close();
        if (brandY != null) brandY.close();
        if (foreign != null) foreign.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        // Two trusted brands => multi-issuer mode: the prod SecurityConfig swaps to the
        // TenancyResourceServerConfig per-issuer resolver, which validates each brand's
        // tokens against its own in-process JWKS and 401s an unknown issuer.
        r.add("app.tenancy.issuers",
                () -> brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        // Neutralise the autoconfigured single-issuer decoder so boot never dials the real
        // public Casdoor (no OIDC discovery / network egress at boot). It is never invoked:
        // isMultiIssuer() is true so the multi-issuer resolver wins.
        r.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> "");
        r.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri", () -> "http://127.0.0.1:0/jwks");
    }

    @Autowired WebTestClient web;
    @Autowired DeviceRowRepository devices;
    @Autowired VpnConfigRowRepository vpnConfigs;
    @Autowired DomainLockRowRepository domainLocks;
    @Autowired AccessSuspensionRowRepository suspensions;
    @Autowired RouteAccessRowRepository routeAccess;
    @Autowired AnnouncementRowRepository announcements;

    @BeforeEach
    void clean() {
        // Each method starts from a known-empty surface so a row-count delta is solely the
        // effect of THAT method's (denied) write.
        devices.deleteAll().block();
        vpnConfigs.deleteAll().block();
        domainLocks.deleteAll().block();
        suspensions.deleteAll().block();
        routeAccess.deleteAll().block();
        announcements.deleteAll().block();
    }

    // ───────────────────────────── token mint helpers ─────────────────────────────

    // Brand-X (DOMAIN_brandx) tokens by role.
    private static String adminX()  { return brandX.mint("admin-x", List.of("admin")); }
    private static String modX()    { return brandX.mint("mod-x", List.of("mod")); }
    private static String userX()   { return brandX.mint("user-x", List.of("user")); }
    // Cross-domain ADMIN: a perfectly valid brand-Y admin token (issuer-derived DOMAIN_brandy).
    // It is a genuine ADMIN, so it passes the /bff/admin/** path gate — but it is NOT a
    // SUPERADMIN, so the @PreAuthorize("hasRole('SUPERADMIN')") method gate denies it 403,
    // identically to a same-domain admin. Used to prove the superadmin cut is role-based and
    // not defeated by being an admin of another brand.
    private static String crossDomainAdmin() { return brandY.mint("admin-y", List.of("admin")); }

    // FORGED: a brand-X admin token whose signature bytes are corrupted.
    private static String forged() {
        String t = brandX.mint("attacker", List.of("admin", "superadmin"));
        return t.substring(0, t.length() - 4) + "AAAA";
    }

    // FOREIGN ISSUER: a well-formed, correctly-signed token from an issuer NOT in
    // app.tenancy.issuers (claims superadmin to prove role-claims can't buy trust).
    private static String foreignIssuer() {
        return foreign.mint("attacker", List.of("admin", "superadmin"));
    }

    // EXPIRED: a token whose iss is the trusted brand-X (so the resolver routes it to
    // brand-X's manager and fetches brand-X's JWKS) but whose exp is in the PAST. It is
    // signed by an ephemeral key whose kid is not in brand-X's JWKS, so BOTH the expiry
    // window AND the signature-key resolution fail-close to the same 401 — a stale/expired
    // token is never accepted on a protected surface. (TestIssuer.mint hard-codes a future
    // exp and does not expose its private key, so an expired token is minted directly here.)
    private static String expiredToken() {
        try {
            RSAKey ephemeral = new RSAKeyGenerator(2048).keyID("expired-kid").generate();
            Instant past = Instant.now().minusSeconds(3600);
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(ephemeral.getKeyID()).build(),
                    new JWTClaimsSet.Builder()
                            .issuer(brandX.issuerUri())
                            .subject("expired-admin")
                            .issueTime(Date.from(past.minusSeconds(300)))
                            .expirationTime(Date.from(past))   // EXPIRED 1h ago
                            .claim("roles", List.of(Map.of("name", "admin"),
                                    Map.of("name", "superadmin")))
                            .claim("name", "expired-admin")
                            .build());
            jwt.sign(new RSASSASigner(ephemeral));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("failed to mint expired test JWT", e);
        }
    }

    // ───────────────────────────── request helpers ─────────────────────────────

    private WebTestClient.ResponseSpec send(HttpMethod method, String uri, String bearer, String body) {
        WebTestClient.RequestBodySpec req = web.method(method).uri(uri)
                .header("Authorization", "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON);
        return (body == null ? req : req.bodyValue(body)).exchange();
    }

    /** Assert a mutation is DENIED with {@code expectedStatus} AND wrote NOTHING: the
     *  backing table's row count is identical before and after. */
    private void deniedAndNoWrite(HttpMethod method, String uri, String bearer, String body,
                                  int expectedStatus, Supplier<Long> rowCount) {
        long before = rowCount.get();
        send(method, uri, bearer, body).expectStatus().isEqualTo(expectedStatus);
        long after = rowCount.get();
        assertThat(after)
                .as("DENIED %s %s must produce NO write (row count unchanged) — verify-never-wrote",
                        method, uri)
                .isEqualTo(before);
    }

    // Valid bodies (so a deny can ONLY be authz, never a 400 body-validation that would
    // mask the real boundary). The owner/domain in these bodies is deliberately a FOREIGN
    // brand to also assert it is never honoured.
    private static final String VPN_BODY = """
            {"domain":"brandx","name":"neg-test","provider":"protonvpn",
             "config":"[Interface]\\nPrivateKey=AA==\\nAddress=10.0.0.2/32\\n[Peer]\\nPublicKey=BB==\\nEndpoint=1.2.3.4:51820\\nAllowedIPs=0.0.0.0/0"}
            """;
    private static final String DEVICE_BODY = """
            {"machineKeyFp":"fp-neg-1","hostname":"neg-host","tailnetId":"tn-1",
             "imageType":"primary","hardwareClass":"server","ownerType":"ADMIN",
             "physicalOwner":"brandx","domain":"brandx","meshId":"mesh-1"}
            """;
    private static final String DOMAIN_BODY = """
            {"clusterDomain":"brandx","displayName":"Brand X"}
            """;
    private static final String ANN_BODY = """
            {"title":"neg","body":"neg-test announcement","surfaces":["home"]}
            """;
    private static final String ROUTE_BODY = """
            {"gateway":"games","urlPattern":"/api/neg/**","rolesCsv":"ROLE_ADMIN","public":false}
            """;
    private static final String OIDC_ROLES_BODY = """
            {"roles":["ROLE_NEG"]}
            """;
    private static final String BACKUP_TOTAL_BODY = """
            {"reason":"neg-test"}
            """;

    // ═══════════════════ 1. SUPERADMIN-only endpoints DENIED to admin/mod/user/cross-domain ═══════════════════
    //
    // These live UNDER /bff/admin/** (coarse ROLE_ADMIN gate) but carry a per-method
    // @PreAuthorize("hasRole('SUPERADMIN')") — OR under /bff/superadmin/** (path-table
    // SUPERADMIN gate). Either way a non-superadmin is 403. verify-never-wrote on each.

    @Test
    void superadminOnly_deviceLicenseRegister_deniedToNonSuperadmins_andNoWrite() {
        String uri = "/bff/admin/device-licenses/register";
        // ADMIN: passes the /bff/admin coarse gate (it IS an admin) but the SUPERADMIN
        // @PreAuthorize denies it.
        deniedAndNoWrite(HttpMethod.POST, uri, adminX(), DEVICE_BODY, 403, this::deviceCount);
        // CROSS-DOMAIN ADMIN: a brand-Y admin is just as denied — the cut is the role, not
        // the brand. Owner/domain in the body (brandx) is irrelevant to the deny.
        deniedAndNoWrite(HttpMethod.POST, uri, crossDomainAdmin(), DEVICE_BODY, 403, this::deviceCount);
        // MOD + USER: denied at the /bff/admin path table (neither has ROLE_ADMIN).
        deniedAndNoWrite(HttpMethod.POST, uri, modX(), DEVICE_BODY, 403, this::deviceCount);
        deniedAndNoWrite(HttpMethod.POST, uri, userX(), DEVICE_BODY, 403, this::deviceCount);
    }

    @Test
    void superadminOnly_deviceLicenseGrantDomain_deniedToNonSuperadmins_andNoWrite() {
        String uri = "/bff/admin/device-licenses/domains/brandx/grant";
        String body = """
                {"operator":"op-x","keyFingerprints":["kf-1"]}
                """;
        deniedAndNoWrite(HttpMethod.POST, uri, adminX(), body, 403, this::deviceCount);
        deniedAndNoWrite(HttpMethod.POST, uri, crossDomainAdmin(), body, 403, this::deviceCount);
        deniedAndNoWrite(HttpMethod.POST, uri, modX(), body, 403, this::deviceCount);
    }

    @Test
    void superadminOnly_egressVpnImport_deniedToNonSuperadmins_andNoWrite() {
        String uri = "/bff/admin/egress-vpn/configs";
        deniedAndNoWrite(HttpMethod.POST, uri, adminX(), VPN_BODY, 403, this::vpnCount);
        deniedAndNoWrite(HttpMethod.POST, uri, crossDomainAdmin(), VPN_BODY, 403, this::vpnCount);
        deniedAndNoWrite(HttpMethod.POST, uri, modX(), VPN_BODY, 403, this::vpnCount);
        deniedAndNoWrite(HttpMethod.POST, uri, userX(), VPN_BODY, 403, this::vpnCount);
    }

    @Test
    void superadminOnly_domainRegistryCreate_deniedToNonSuperadmins_andNoWrite() {
        // /bff/admin/domains POST = @PreAuthorize SUPERADMIN. No device/vpn table to read;
        // assert the deny only (the create writes to a domain-registry table we don't seed).
        String uri = "/bff/admin/domains";
        send(HttpMethod.POST, uri, adminX(), DOMAIN_BODY).expectStatus().isEqualTo(403);
        send(HttpMethod.POST, uri, crossDomainAdmin(), DOMAIN_BODY).expectStatus().isEqualTo(403);
        send(HttpMethod.POST, uri, modX(), DOMAIN_BODY).expectStatus().isEqualTo(403);
        send(HttpMethod.POST, uri, userX(), DOMAIN_BODY).expectStatus().isEqualTo(403);
    }

    @Test
    void superadminOnly_cloudBackupTotal_deniedToNonSuperadmins() {
        // /bff/superadmin/** path-table SUPERADMIN gate: an ADMIN (even cross-domain), MOD,
        // USER are all denied at the filter chain BEFORE any controller logic.
        String uri = "/bff/superadmin/cloud-backups/total";
        send(HttpMethod.POST, uri, adminX(), BACKUP_TOTAL_BODY).expectStatus().isEqualTo(403);
        send(HttpMethod.POST, uri, crossDomainAdmin(), BACKUP_TOTAL_BODY).expectStatus().isEqualTo(403);
        send(HttpMethod.POST, uri, modX(), BACKUP_TOTAL_BODY).expectStatus().isEqualTo(403);
        send(HttpMethod.POST, uri, userX(), BACKUP_TOTAL_BODY).expectStatus().isEqualTo(403);
    }

    // ═══════════════════ 2. ADMIN own-domain actions DENIED to mod/user ═══════════════════
    //
    // /bff/admin/** path table requires ROLE_ADMIN|ROLE_SUPERADMIN. A MOD/USER token carries
    // neither, so the filter chain denies 403 before the controller runs. verify-never-wrote.

    @Test
    void adminAction_suspend_deniedToModAndUser_andNoWrite() {
        String uri = "/bff/admin/access-roles/ROLE_MATRIX/victimuser";
        String body = """
                {"reason":"neg-test"}
                """;
        deniedAndNoWrite(HttpMethod.POST, uri, modX(), body, 403, this::suspensionCount);
        deniedAndNoWrite(HttpMethod.POST, uri, userX(), body, 403, this::suspensionCount);
    }

    @Test
    void adminAction_domainLock_deniedToModAndUser_andNoWrite() {
        String uri = "/bff/admin/domain-lock/ROLE_MATRIX_DOMAINLOCKED/victimuser";
        String body = """
                {"reason":"neg-test"}
                """;
        deniedAndNoWrite(HttpMethod.POST, uri, modX(), body, 403, this::domainLockCount);
        deniedAndNoWrite(HttpMethod.POST, uri, userX(), body, 403, this::domainLockCount);
    }

    @Test
    void adminAction_routeAccessAdd_deniedToModAndUser_andNoWrite() {
        String uri = "/bff/admin/route-access";
        deniedAndNoWrite(HttpMethod.POST, uri, modX(), ROUTE_BODY, 403, this::routeAccessCount);
        deniedAndNoWrite(HttpMethod.POST, uri, userX(), ROUTE_BODY, 403, this::routeAccessCount);
    }

    @Test
    void adminAction_announcementCreate_deniedToModAndUser_andNoWrite() {
        String uri = "/bff/admin/announcements";
        deniedAndNoWrite(HttpMethod.POST, uri, modX(), ANN_BODY, 403, this::announcementCount);
        deniedAndNoWrite(HttpMethod.POST, uri, userX(), ANN_BODY, 403, this::announcementCount);
    }

    @Test
    void adminAction_oidcProviderRolesPut_deniedToModAndUser() {
        String uri = "/bff/admin/oidc-providers/casdoor/roles";
        send(HttpMethod.PUT, uri, modX(), OIDC_ROLES_BODY).expectStatus().isEqualTo(403);
        send(HttpMethod.PUT, uri, userX(), OIDC_ROLES_BODY).expectStatus().isEqualTo(403);
    }

    // ═══════════════════ 3. Token integrity / fail-closed -> 401 ═══════════════════
    //
    // A forged-signature, foreign-issuer, or expired token is rejected with 401 on a
    // protected surface — never silently accepted, never anonymous-allowed. We probe a
    // SUPERADMIN-only mutation surface: a real superadmin token would 200/404, so a 401 here
    // proves the token never authenticated (fail-closed), independent of the role gate.

    @Test
    void forgedSignatureToken_is401_andNoWrite() {
        deniedAndNoWrite(HttpMethod.POST, "/bff/admin/egress-vpn/configs", forged(), VPN_BODY,
                401, this::vpnCount);
    }

    @Test
    void foreignIssuerToken_is401_failClosed_andNoWrite() {
        // A correctly-signed token from an issuer NOT in app.tenancy.issuers — claiming
        // superadmin — still gets NO manager from the resolver and 401s. Role claims cannot
        // buy trust an untrusted issuer never had.
        deniedAndNoWrite(HttpMethod.POST, "/bff/admin/device-licenses/register", foreignIssuer(),
                DEVICE_BODY, 401, this::deviceCount);
    }

    @Test
    void expiredToken_is401_andNoWrite() {
        deniedAndNoWrite(HttpMethod.POST, "/bff/admin/egress-vpn/configs", expiredToken(), VPN_BODY,
                401, this::vpnCount);
    }

    @Test
    void noBearer_onProtectedSurface_is401() {
        web.post().uri("/bff/admin/egress-vpn/configs")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(VPN_BODY)
                .exchange().expectStatus().isEqualTo(401);
    }

    @Test
    void garbageBearer_is401() {
        web.post().uri("/bff/admin/egress-vpn/configs")
                .header("Authorization", "Bearer not-a-jwt")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(VPN_BODY)
                .exchange().expectStatus().isEqualTo(401);
    }

    // ───────────────────────────── re-read counts ─────────────────────────────

    private long deviceCount()       { return n(devices.count().block()); }
    private long vpnCount()          { return n(vpnConfigs.count().block()); }
    private long domainLockCount()   { return n(domainLocks.count().block()); }
    private long suspensionCount()   { return n(suspensions.count().block()); }
    private long routeAccessCount()  { return n(routeAccess.count().block()); }
    private long announcementCount() { return n(announcements.count().block()); }

    private static long n(Long v) { return v == null ? 0L : v; }
}
