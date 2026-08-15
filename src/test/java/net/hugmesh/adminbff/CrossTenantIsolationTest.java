package net.hugmesh.adminbff;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.adminbff.announcement.AnnouncementRowRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessRowRepository;
import net.hugmesh.adminbff.routeaccess.RouteRule;
import net.hugmesh.adminbff.suspension.AccessSuspensionRowRepository;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;
import net.hugmesh.adminbff.support.ExcludeTestSourcedControllers;
import net.hugmesh.adminbff.testsupport.TestIssuer;
import net.hugmesh.authcore.account.AllowlistRepository;
import net.hugmesh.authcore.account.NamespaceGrantRepository;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CROSS-TENANT ISOLATION — HTTP-boundary proof that the domain-scoping mechanism
 * (derived from the cryptographically-validated JWT issuer via {@link
 * net.hugmesh.commons.security.PrincipalDomain}) filters data correctly at the
 * HTTP response level. This is the missing layer identified in the audit: existing
 * service-layer DomainScope tests ({@link announcement.AnnouncementDomainScopeTest},
 * {@link suspension.AccessSuspensionDomainScopeTest}, etc.) prove the SQL predicate
 * path; {@link config.MultiIssuerSecuritySliceTest} proves the authority-stamping and
 * 401 fail-closed; {@link security.RawApiDenyMatrixTest} proves the SUPERADMIN-only
 * role gate denies a cross-domain admin. NONE of those verify: <em>does the HTTP
 * response body returned to a brand-X admin contain ONLY brand-X rows</em>?
 *
 * <p>Specifically this suite asserts the four HTTP-level cross-tenant isolation
 * keystones:
 * <ol>
 *   <li><b>READ isolation (DENY)</b> — a brand-X admin's GET returns ONLY brand-X
 *       rows; brand-Y rows are absent from the response body. The deny is not a 403;
 *       it is an empty/filtered JSON response. Verified across two representative
 *       surfaces: announcements and route-access rules.</li>
 *   <li><b>READ isolation SUPERADMIN (ALLOW)</b> — a SUPERADMIN's GET across the same
 *       surface includes BOTH brands' rows (unscoped).</li>
 *   <li><b>WRITE cross-brand no-op (DENY)</b> — a brand-X admin trying to DELETE a
 *       brand-Y row receives a non-error status (the row is silently not in scope) but
 *       the brand-Y row survives in the database (verify-never-wrote).</li>
 *   <li><b>WRITE scoping (ALLOW)</b> — a brand-X admin can create rows that are
 *       stamped with brand-X's domain (not a user-supplied value), visible to brand-X
 *       admins and to SUPERADMIN, invisible to brand-Y admins.</li>
 * </ol>
 *
 * <p><b>Architecture</b> follows {@link security.RawApiDenyMatrixTest}: two trusted
 * {@link TestIssuer} in-process JWKS servers ({@code brandX} / {@code brandY}) are
 * registered via {@code @DynamicPropertySource} so the production
 * {@code TenancyResourceServerConfig} activates the real per-issuer resolver. Every
 * token is a REAL RS256-signed JWT; the real production filter chain, method security,
 * controllers, services, and Postgres store are all exercised — no mocks. A third
 * {@code foreign} issuer is NOT listed in {@code app.tenancy.issuers}, so its tokens
 * 401 (fail-closed, asserted in the dedicated token-integrity nested class here to
 * confirm the scan surface is enforced on cross-tenant reads too).
 *
 * <p><b>MUTATION-RESISTANT (verify-never-wrote):</b> cross-brand DELETE denies are
 * confirmed by re-reading the backing table after the request and asserting row count
 * is unchanged. A silently fail-open scope guard that lets a cross-brand delete
 * through would cause the post-request row count to drop, failing the assertion.
 *
 * <p>Wiring: {@link ExcludeTestSourcedControllers} withdraws the TOP-LEVEL package-private
 * probe controllers declared alongside the config slice tests, which a component scan would
 * otherwise sweep into this full-context boot — they collide with the real controllers
 * ("Ambiguous mapping"). It selects by CODE SOURCE, so a probe added later is covered without
 * editing anything here.
 *
 * <p>This class previously carried its own two-name copy of that list. Migrating it was hygiene
 * — one definition of "test-sourced" across all four full-context tests — not a fix for a defect
 * it suffered from: this matrix never requests a {@code /bff/internal} path, so the third probe
 * ({@code InternalProbes}) missing from the old list changed nothing here.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient(timeout = "PT30S")
@ActiveProfiles("test")
@Import(ExcludeTestSourcedControllers.class)
class CrossTenantIsolationTest extends AdminBffPostgresTestSupport {

    // ── Two trusted brands + one untrusted issuer ────────────────────────────────

    private static TestIssuer brandX;
    private static TestIssuer brandY;
    private static TestIssuer foreign;   // NOT in app.tenancy.issuers → 401

    @BeforeAll
    static void startIssuers() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        foreign = new TestIssuer();
    }

    @AfterAll
    static void stopIssuers() {
        if (brandX != null) brandX.close();
        if (brandY != null) brandY.close();
        if (foreign != null) foreign.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        // Two trusted brands → multi-issuer mode: the prod SecurityConfig swaps to the
        // TenancyResourceServerConfig per-issuer resolver (isMultiIssuer() = true).
        r.add("app.tenancy.issuers",
                () -> brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        // Neutralise the autoconfigured single-issuer decoder so boot never dials a real
        // Casdoor endpoint. The multi-issuer resolver wins (isMultiIssuer = true) and the
        // single-issuer jwk-set-uri decoder is never consulted.
        r.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> "");
        r.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> "http://127.0.0.1:0/jwks");
    }

    @Autowired WebTestClient web;

    // Direct repository access for verify-never-wrote assertions and seed inserts.
    @Autowired AnnouncementRowRepository announcements;
    @Autowired RouteAccessRowRepository routeAccessRows;
    @Autowired RouteAccessRepository routeAccessRepo;
    @Autowired AccessSuspensionRowRepository suspensions;
    @Autowired AllowlistRepository allowlistRepo;
    @Autowired NamespaceGrantRepository namespaceGrantRepo;

    @BeforeEach
    void cleanAllTables() {
        announcements.deleteAll().block();
        routeAccessRows.deleteAll().block();
        suspensions.deleteAll().block();
        allowlistRepo.deleteAll().block();
        namespaceGrantRepo.deleteAll().block();
    }

    // ── Token mint helpers ───────────────────────────────────────────────────────

    /** Brand-X ADMIN token — issuer-derived DOMAIN_brandx, ROLE_ADMIN. */
    private static String adminX() {
        return brandX.mint("admin-x", List.of("admin"));
    }

    /** Brand-Y ADMIN token — issuer-derived DOMAIN_brandy, ROLE_ADMIN. */
    private static String adminY() {
        return brandY.mint("admin-y", List.of("admin"));
    }

    /** Brand-X SUPERADMIN token — ROLE_SUPERADMIN, unscoped (sees all domains). */
    private static String superadmin() {
        return brandX.mint("superadmin-x", List.of("superadmin"));
    }

    /** Foreign-issuer ADMIN token — NOT in app.tenancy.issuers → 401 fail-closed. */
    private static String foreignAdmin() {
        return foreign.mint("foreign-admin", List.of("admin"));
    }

    // ── HTTP request helper ──────────────────────────────────────────────────────

    private WebTestClient.ResponseSpec send(String method, String uri, String bearer, String body) {
        var spec = web.method(org.springframework.http.HttpMethod.valueOf(method))
                .uri(uri)
                .header("Authorization", "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON);
        return (body == null ? spec : spec.bodyValue(body)).exchange();
    }

    // ── Announcement seed helper ─────────────────────────────────────────────────

    /**
     * Seed a minimal announcement stamped with {@code domain} directly via the
     * repository (bypasses HTTP + auth), so we control which brand's row exists
     * before the test drives the HTTP assertion.
     */
    private String seedAnnouncement(String domain, String title) {
        java.util.UUID id = java.util.UUID.randomUUID();
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        net.hugmesh.adminbff.announcement.AnnouncementRow row =
                new net.hugmesh.adminbff.announcement.AnnouncementRow(
                        id, title, "<p>hi</p>", "html", "draft",
                        true, false, false, false, 0,
                        null, null, "UTC", true,
                        "seed-admin", null, now, now, domain, true);
        announcements.save(row).block();
        return id.toString();
    }

    // ── Route-access seed helper ─────────────────────────────────────────────────

    /**
     * Seed a route-access rule stamped with {@code domain} directly, returning its
     * persisted {@link RouteRule} (with the generated id).
     */
    private RouteRule seedRouteRule(String domain, String urlPattern) {
        RouteRule rule = new RouteRule(null, "gateway", urlPattern, "ROLE_ADMIN",
                null, true, domain);
        return routeAccessRepo.add(rule).block();
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // 1. READ ISOLATION — announcements
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * HTTP READ cross-tenant isolation on the announcements surface
     * ({@code GET /bff/admin/announcements}).
     *
     * <p>The service-layer isolation is covered by
     * {@link announcement.AnnouncementDomainScopeTest}. This nested class adds the
     * missing HTTP-level layer: does the HTTP response body received by a brand-X
     * admin contain ONLY brand-X rows, and is it empty when no brand-X rows exist?
     */
    @Nested
    class AnnouncementReadIsolation {

        /**
         * CROSS-USER DENY (HTTP) — brand-X admin GET /bff/admin/announcements returns
         * ONLY brand-X rows; brand-Y rows are absent from the response body.
         *
         * <p>Mutation-sensitive: the scoped SQL predicate ({@code WHERE domain = brandx})
         * is the sole gate. Remove it and brand-Y's rows appear in the response, failing
         * the {@code doesNotContain} assertion.
         */
        @Test
        void brandXAdmin_listAnnouncements_seesOnlyBrandXRows_notBrandY() {
            seedAnnouncement("brandx", "brandx-announcement");
            seedAnnouncement("brandy", "brandy-announcement");

            send("GET", "/bff/admin/announcements", adminX(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body)
                                .as("brand-X admin list must include the brand-X announcement")
                                .contains("brandx-announcement");
                        assertThat(body)
                                .as("brand-X admin list must NOT include the brand-Y announcement — " +
                                        "cross-tenant data must be absent, not just gated 403")
                                .doesNotContain("brandy-announcement");
                    });
        }

        /**
         * CROSS-USER DENY (HTTP) — brand-Y admin sees only brand-Y rows; brand-X rows
         * absent. Symmetric to the above, proving the filter is applied for both
         * directions of the domain boundary.
         */
        @Test
        void brandYAdmin_listAnnouncements_seesOnlyBrandYRows_notBrandX() {
            seedAnnouncement("brandx", "brandx-announcement");
            seedAnnouncement("brandy", "brandy-announcement");

            send("GET", "/bff/admin/announcements", adminY(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).contains("brandy-announcement");
                        assertThat(body).doesNotContain("brandx-announcement");
                    });
        }

        /**
         * CROSS-USER DENY (HTTP, empty response) — a brand-X admin whose brand has NO
         * rows sees an empty list, not brand-Y's data. This is the "fail-closed, not
         * fall-through" assertion: the predicate must return nothing, not default to
         * all-brands.
         */
        @Test
        void brandXAdmin_listAnnouncements_emptyWhenNoBrandXRowsExist_evenIfBrandYHasRows() {
            seedAnnouncement("brandy", "brandy-announcement");
            // NO brand-X rows inserted.

            send("GET", "/bff/admin/announcements", adminX(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> assertThat(body)
                            .as("brand-X sees empty list — NOT brand-Y's data (fail-closed)")
                            .doesNotContain("brandy-announcement")
                            // The announcements list wrapper: expect the array to be empty.
                            .contains("\"announcements\":[]"));
        }

        /**
         * MULTIUSER-SITUATIONAL ALLOW — SUPERADMIN GET /bff/admin/announcements includes
         * BOTH brands' rows (unscoped). Verifies the superadmin bypass path executes the
         * correct unscoped query at the HTTP response level (not just service-unit).
         */
        @Test
        void superadmin_listAnnouncements_seesBothBrands() {
            seedAnnouncement("brandx", "brandx-ann");
            seedAnnouncement("brandy", "brandy-ann");

            send("GET", "/bff/admin/announcements", superadmin(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).contains("brandx-ann");
                        assertThat(body).contains("brandy-ann");
                    });
        }

        /**
         * CROSS-USER DENY (HTTP, GET-by-id) — brand-X admin cannot resolve brand-Y's
         * announcement by id. The response must be 404 (invisible, not a leaking 200 or
         * 403). "Invisible" is the correct UX for cross-brand ids: a 403 would reveal
         * that the id exists; a 404 reveals nothing.
         */
        @Test
        void brandXAdmin_getAnnouncementById_returnsMissing_forBrandYId() {
            String yId = seedAnnouncement("brandy", "brandy-secret");

            send("GET", "/bff/admin/announcements/" + yId, adminX(), null)
                    .expectStatus().isNotFound();
        }

        /**
         * MULTIUSER-SITUATIONAL ALLOW — SUPERADMIN GET-by-id resolves any brand's id.
         */
        @Test
        void superadmin_getAnnouncementById_resolvesAnyBrand() {
            String yId = seedAnnouncement("brandy", "brandy-visible-to-sa");

            send("GET", "/bff/admin/announcements/" + yId, superadmin(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> assertThat(body).contains("brandy-visible-to-sa"));
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // 2. READ ISOLATION — route-access rules
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * HTTP READ cross-tenant isolation on the route-access surface
     * ({@code GET /bff/admin/route-access}). The service-layer isolation is covered by
     * {@link routeaccess.RouteAccessDomainScopeTest}; this adds the HTTP body level.
     */
    @Nested
    class RouteAccessReadIsolation {

        @Test
        void brandXAdmin_listRouteRules_seesOnlyBrandXRules() {
            seedRouteRule("brandx", "/api/brandx/**");
            seedRouteRule("brandy", "/api/brandy/**");

            send("GET", "/bff/admin/route-access", adminX(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).contains("/api/brandx/**");
                        assertThat(body).doesNotContain("/api/brandy/**");
                    });
        }

        @Test
        void brandYAdmin_listRouteRules_seesOnlyBrandYRules() {
            seedRouteRule("brandx", "/api/brandx/**");
            seedRouteRule("brandy", "/api/brandy/**");

            send("GET", "/bff/admin/route-access", adminY(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).contains("/api/brandy/**");
                        assertThat(body).doesNotContain("/api/brandx/**");
                    });
        }

        @Test
        void brandXAdmin_listRouteRules_emptyWhenNoBrandXRulesExist() {
            seedRouteRule("brandy", "/api/brandy-only/**");

            send("GET", "/bff/admin/route-access", adminX(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> assertThat(body).doesNotContain("/api/brandy-only/**"));
        }

        @Test
        void superadmin_listRouteRules_seesBothBrands() {
            seedRouteRule("brandx", "/api/brandx/**");
            seedRouteRule("brandy", "/api/brandy/**");

            send("GET", "/bff/admin/route-access", superadmin(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).contains("/api/brandx/**");
                        assertThat(body).contains("/api/brandy/**");
                    });
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // 3. WRITE ISOLATION — domain stamp on create, cross-brand DELETE is a no-op
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * HTTP WRITE cross-tenant isolation: create stamps the correct issuer-derived domain
     * (never a user-controlled value), and a cross-brand DELETE is silently a no-op at
     * the HTTP surface while the row survives in the database (verify-never-wrote).
     */
    @Nested
    class WriteIsolation {

        /**
         * USER-SITUATIONAL ALLOW — a brand-X admin POSTs an announcement and the
         * created row carries {@code domain = brandx} (from the validated JWT issuer),
         * not any body field. The row is then visible ONLY to brand-X and SUPERADMIN,
         * invisible to brand-Y (HTTP-verified).
         *
         * <p>This closes the "domain stamp is the validated iss, not a user-settable
         * claim" assertion at the HTTP level: even if the POST body contained a
         * {@code domain} field, the service stamps from PrincipalDomain.
         */
        @Test
        void brandXAdmin_createAnnouncement_stampsDomainFromIssuer_notFromBody() {
            String body = """
                    {"title":"X-only","body_html":"<p>x</p>","target_home":true}
                    """;
            send("POST", "/bff/admin/announcements", adminX(), body)
                    .expectStatus().isCreated()
                    .expectBody(String.class)
                    .value(created -> {
                        assertThat(created).contains("X-only");
                        // domain is @JsonIgnore — it must NOT appear in the JSON response.
                        assertThat(created).doesNotContain("\"domain\"");
                    });

            // The created row is visible to brand-X but NOT to brand-Y.
            send("GET", "/bff/admin/announcements", adminX(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(list -> assertThat(list).contains("X-only"));

            send("GET", "/bff/admin/announcements", adminY(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(list -> assertThat(list).doesNotContain("X-only"));

            // SUPERADMIN sees it.
            send("GET", "/bff/admin/announcements", superadmin(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(list -> assertThat(list).contains("X-only"));
        }

        /**
         * CROSS-USER DENY (write, verify-never-wrote) — a brand-X admin sends
         * {@code DELETE /bff/admin/announcements/{yId}} where {@code yId} belongs to
         * brand-Y. The request must NOT return an error (the brand-Y id is simply
         * invisible to brand-X's scoped query) and the brand-Y row must still exist
         * in the database afterwards.
         *
         * <p>Mutation-resistant: if the scoped DELETE predicate is removed (the guard
         * fails open), the row is deleted, the re-read finds 0 announcements, and
         * {@code hasSize(1)} fails.
         */
        @Test
        void brandXAdmin_deleteAnnouncementBelongingToBrandY_isNoOp_rowSurvives() {
            String yId = seedAnnouncement("brandy", "brandy-protected");

            // Pre-condition: the row exists.
            assertThat(announcements.count().block()).isEqualTo(1L);

            // Brand-X admin deletes by brand-Y's id.
            send("DELETE", "/bff/admin/announcements/" + yId, adminX(), null)
                    // The 404 here is the correct "invisible" response: the scoped find
                    // returns empty, AnnouncementService.delete() propagates notFound().
                    // Whether the HTTP status is 404 or 204 is an impl detail — the
                    // load-bearing assertion is the row-count below.
                    .expectStatus().value(status ->
                            assertThat(status).as("brand-X delete of brand-Y id must not return 2xx success")
                                    .isNotEqualTo(204));

            // Verify-never-wrote: the brand-Y row must still exist.
            assertThat(announcements.count().block())
                    .as("brand-Y announcement must survive a brand-X admin's DELETE — " +
                            "cross-tenant write isolation (verify-never-wrote)")
                    .isEqualTo(1L);
        }

        /**
         * USER-SITUATIONAL ALLOW — a brand-X admin can delete their OWN announcement
         * (same domain). Confirms the verify-never-wrote gate above is not a false
         * negative (the happy path also works).
         */
        @Test
        void brandXAdmin_deleteOwnAnnouncement_succeeds_rowRemoved() {
            String xId = seedAnnouncement("brandx", "brandx-own");

            send("DELETE", "/bff/admin/announcements/" + xId, adminX(), null)
                    .expectStatus().isNoContent();

            assertThat(announcements.count().block())
                    .as("brand-X admin's own announcement must be deleted")
                    .isEqualTo(0L);
        }

        /**
         * CROSS-USER DENY (route-access DELETE, verify-never-wrote) — a brand-X admin
         * cannot delete brand-Y's route-access rule. The {@code RouteAccessRepository}
         * scoped delete returns {@code rows-deleted = 0}, the rule survives.
         *
         * <p>This exercises the route-access domain-scoped DELETE path at the HTTP
         * level, complementing the service-unit test in
         * {@link routeaccess.RouteAccessDomainScopeTest}.
         */
        @Test
        void brandXAdmin_deleteRouteAccessRuleBelongingToBrandY_isNoOp_rowSurvives() {
            RouteRule yRule = seedRouteRule("brandy", "/api/brandy-protected/**");

            assertThat(routeAccessRows.count().block()).isEqualTo(1L);

            // Brand-X admin issues the delete.
            send("DELETE", "/bff/admin/route-access/" + yRule.id(), adminX(), null)
                    .expectStatus().value(status ->
                            assertThat(status).as("cross-brand DELETE must not be 204 success")
                                    .isNotEqualTo(204));

            // Verify-never-wrote: brand-Y's rule survives.
            assertThat(routeAccessRows.count().block())
                    .as("brand-Y route-access rule must survive a brand-X admin's DELETE")
                    .isEqualTo(1L);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // 4. TOKEN INTEGRITY on cross-tenant READ surface — fail-closed at the HTTP layer
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * Confirms the fail-closed posture that underpins ALL cross-tenant isolation: if
     * the issuer-derived DOMAIN authority cannot be established (untrusted issuer,
     * tampered signature, no token), the request is 401 BEFORE any domain-scoped
     * data lookup runs. Complements {@link config.SingleIssuerJwtFailClosedTest} and
     * {@link config.MultiIssuerSecuritySliceTest} by exercising the same boundary on
     * a concrete READ surface (not a probe endpoint).
     */
    @Nested
    class TokenIntegrityOnCrossTenantReadSurface {

        @Test
        void foreignIssuerToken_on_announcementList_is401_failClosed() {
            // The foreign issuer is NOT listed in app.tenancy.issuers. The per-issuer
            // resolver finds no manager → 401, fail-closed. Even if it claimed admin
            // role, role-claims cannot buy trust an untrusted issuer never had.
            seedAnnouncement("brandx", "x-ann");
            send("GET", "/bff/admin/announcements", foreignAdmin(), null)
                    .expectStatus().isUnauthorized();
        }

        @Test
        void tamperedSignatureToken_on_announcementList_is401() {
            String token = brandX.mint("admin-x", List.of("admin"));
            String tampered = token.substring(0, token.length() - 4) + "AAAA";
            send("GET", "/bff/admin/announcements", tampered, null)
                    .expectStatus().isUnauthorized();
        }

        @Test
        void noBearer_on_announcementList_is401() {
            web.get().uri("/bff/admin/announcements")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        void crossBrandSignatureForge_brandXKeyWithBrandYIssuer_is401() {
            // SECURITY: a token whose payload claims brand-Y's iss but is SIGNED by
            // brand-X's private key. The resolver selects brand-Y's manager (off iss)
            // and fetches brand-Y's JWKS — brand-X's signature does NOT verify against
            // brand-Y's public key → 401. An attacker cannot mint a brand-Y identity
            // with a key brand-Y never published.
            String forged = brandX.mintWithClaims("attacker",
                    Map.of(
                            "iss", brandY.issuerUri(),
                            "roles", List.of(Map.of("name", "admin"))));
            send("GET", "/bff/admin/announcements", forged, null)
                    .expectStatus().isUnauthorized();
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // 5. CONCURRENT cross-brand writes — both succeed, scoped reads remain isolated
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * CONCURRENT writes by two brand admins writing simultaneously should not corrupt
     * each other's tenant isolation. Both inserts land; each brand admin then reads
     * only their own row. This is the HTTP-level equivalent of
     * {@link suspension.AccessSuspensionDomainScopeTest.Concurrent}.
     */
    @Nested
    class ConcurrentCrossBrandWrites {

        @Test
        void concurrentAnnouncementCreates_bothBrandsSucceed_eachAdminSeesOwn()
                throws InterruptedException {
            String bodyX = "{\"title\":\"X-concurrent\",\"body_html\":\"<p>x</p>\",\"target_home\":true}";
            String bodyY = "{\"title\":\"Y-concurrent\",\"body_html\":\"<p>y</p>\",\"target_home\":true}";

            // Fire both creates in parallel.
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch done = new CountDownLatch(2);
            AtomicBoolean xOk = new AtomicBoolean(false);
            AtomicBoolean yOk = new AtomicBoolean(false);

            Thread threadX = new Thread(() -> {
                ready.countDown();
                try { ready.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                try {
                    send("POST", "/bff/admin/announcements", adminX(), bodyX)
                            .expectStatus().isCreated();
                    xOk.set(true);
                } finally {
                    done.countDown();
                }
            });
            Thread threadY = new Thread(() -> {
                ready.countDown();
                try { ready.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                try {
                    send("POST", "/bff/admin/announcements", adminY(), bodyY)
                            .expectStatus().isCreated();
                    yOk.set(true);
                } finally {
                    done.countDown();
                }
            });

            threadX.start();
            threadY.start();
            done.await(20, TimeUnit.SECONDS);

            assertThat(xOk.get()).as("brand-X concurrent create must succeed").isTrue();
            assertThat(yOk.get()).as("brand-Y concurrent create must succeed").isTrue();

            // After both writes, each admin sees only their own row.
            send("GET", "/bff/admin/announcements", adminX(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).contains("X-concurrent");
                        assertThat(body).doesNotContain("Y-concurrent");
                    });

            send("GET", "/bff/admin/announcements", adminY(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).contains("Y-concurrent");
                        assertThat(body).doesNotContain("X-concurrent");
                    });

            // SUPERADMIN sees both.
            send("GET", "/bff/admin/announcements", superadmin(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).contains("X-concurrent");
                        assertThat(body).contains("Y-concurrent");
                    });
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // 5. ALLOWLIST CROSS-TENANT ISOLATION (changeset 220)
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * HTTP cross-tenant isolation on the allowlist surface ({@code GET / POST / DELETE
     * /bff/admin/allowlist}) — closes the gap identified in the IDOR audit where
     * brand-X admins could read, add, and remove brand-Y's registration allowlist.
     *
     * <p>Complements {@link net.hugmesh.authcore.account.AccountStoreDomainScopeTest}
     * (service-layer proof) with the HTTP-level assertion: does the response body
     * contain only the caller's brand's entries?
     */
    @Nested
    class AllowlistIsolation {

        @Test
        void brandXAdmin_listAllowlist_seesOnlyBrandXEmails() {
            // Seed two emails, one per brand, directly via the repository.
            seedEmail("alice@x.com", "brandx");
            seedEmail("bob@y.com", "brandy");

            send("GET", "/bff/admin/allowlist", adminX(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).as("brand-X email must be visible to brand-X admin")
                                .contains("alice@x.com");
                        assertThat(body).as("brand-Y email must NOT appear in brand-X admin's list")
                                .doesNotContain("bob@y.com");
                    });
        }

        @Test
        void brandYAdmin_listAllowlist_seesOnlyBrandYEmails() {
            seedEmail("alice@x.com", "brandx");
            seedEmail("bob@y.com", "brandy");

            send("GET", "/bff/admin/allowlist", adminY(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).as("brand-Y email must be visible to brand-Y admin")
                                .contains("bob@y.com");
                        assertThat(body).as("brand-X email must NOT appear in brand-Y admin's list")
                                .doesNotContain("alice@x.com");
                    });
        }

        @Test
        void superadmin_listAllowlist_seesAllBrands() {
            seedEmail("alice@x.com", "brandx");
            seedEmail("bob@y.com", "brandy");

            send("GET", "/bff/admin/allowlist", superadmin(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).contains("alice@x.com");
                        assertThat(body).contains("bob@y.com");
                    });
        }

        @Test
        void brandXAdmin_inviteEmail_stampsOwnDomain() {
            send("POST", "/bff/admin/allowlist", adminX(),
                    "{\"email\":\"newuser@x.com\"}")
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> assertThat(body).contains("newuser@x.com"));

            // Brand-Y cannot see it.
            send("GET", "/bff/admin/allowlist", adminY(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> assertThat(body).doesNotContain("newuser@x.com"));
        }

        @Test
        void brandXAdmin_uninvite_cannotDeleteBrandYEmail_verifyNeverWrote() {
            seedEmail("shared@x.com", "brandx");
            seedEmail("shared@x.com", "brandy");

            long beforeCount = allowlistRepo.count().block();

            // brand-X admin tries to delete the email — domain-scoped DELETE only touches brandx row.
            send("DELETE", "/bff/admin/allowlist", adminX(),
                    "{\"email\":\"shared@x.com\"}")
                    .expectStatus().isOk();

            long afterCount = allowlistRepo.count().block();
            // Only 1 row deleted (brand-X's); brand-Y's row survives.
            assertThat(afterCount).as("brand-Y row must survive brand-X admin's delete")
                    .isEqualTo(beforeCount - 1);
        }

        /** Seed an email allowlist entry directly via the repository. */
        private void seedEmail(String email, String domain) {
            allowlistRepo.insertIfAbsent("google", email.toLowerCase(), domain).block();
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // 6. NAMESPACE-GRANT CROSS-TENANT ISOLATION (changeset 220)
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * HTTP cross-tenant isolation on the namespace-grant surface
     * ({@code GET / POST / DELETE /bff/admin/namespace-access}).
     */
    @Nested
    class NamespaceGrantIsolation {

        @Test
        void brandXAdmin_listGrants_seesOnlyBrandXGrants() {
            seedGrant("alice", "hugmesh-pki", "brandx");
            seedGrant("bob", "hugmesh-backend", "brandy");

            send("GET", "/bff/admin/namespace-access", adminX(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).as("brand-X grant must appear for brand-X admin")
                                .contains("alice");
                        assertThat(body).as("brand-Y grant must NOT appear for brand-X admin")
                                .doesNotContain("bob");
                    });
        }

        @Test
        void brandYAdmin_listGrants_seesOnlyBrandYGrants() {
            seedGrant("alice", "hugmesh-pki", "brandx");
            seedGrant("bob", "hugmesh-backend", "brandy");

            send("GET", "/bff/admin/namespace-access", adminY(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).as("brand-Y grant must appear for brand-Y admin")
                                .contains("bob");
                        assertThat(body).as("brand-X grant must NOT appear for brand-Y admin")
                                .doesNotContain("alice");
                    });
        }

        @Test
        void superadmin_listGrants_seesAllBrands() {
            seedGrant("alice", "hugmesh-pki", "brandx");
            seedGrant("bob", "hugmesh-backend", "brandy");

            send("GET", "/bff/admin/namespace-access", superadmin(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> {
                        assertThat(body).contains("alice");
                        assertThat(body).contains("bob");
                    });
        }

        @Test
        void brandXAdmin_grant_stampsOwnDomain() {
            send("POST", "/bff/admin/namespace-access", adminX(),
                    "{\"user\":\"carol\",\"namespace\":\"observability\"}")
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> assertThat(body).contains("carol"));

            // Brand-Y cannot see it.
            send("GET", "/bff/admin/namespace-access", adminY(), null)
                    .expectStatus().isOk()
                    .expectBody(String.class)
                    .value(body -> assertThat(body).doesNotContain("carol"));
        }

        @Test
        void brandXAdmin_revoke_cannotDeleteBrandYGrant_verifyNeverWrote() {
            seedGrant("dave", "observability", "brandx");
            seedGrant("dave", "observability", "brandy");

            long beforeCount = namespaceGrantRepo.count().block();

            send("DELETE", "/bff/admin/namespace-access", adminX(),
                    "{\"user\":\"dave\",\"namespace\":\"observability\"}")
                    .expectStatus().isOk();

            long afterCount = namespaceGrantRepo.count().block();
            assertThat(afterCount).as("brand-Y grant row must survive brand-X admin's delete")
                    .isEqualTo(beforeCount - 1);
        }

        private void seedGrant(String grantee, String namespace, String domain) {
            namespaceGrantRepo.insertIfAbsent(grantee.toLowerCase(), namespace, domain).block();
        }
    }
}
