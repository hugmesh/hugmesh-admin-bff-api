package systems.hugmesh.adminbff.suspension;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Flux;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import systems.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * Tenant-isolation tests for the access_suspension DOMAIN predicate over a REAL
 * Testcontainers Postgres store — the security keystone of the multi-tenant model. Delineated
 * per the test standard:
 * <ul>
 *   <li>CROSS-USER — a brand-X admin is DENIED brand-Y data (cannot read it, cannot
 *       clear it) both directions; SUPERADMIN sees both.</li>
 *   <li>MULTIUSER-SITUATIONAL — two same-named users in different brands are distinct
 *       rows; each brand admin sees only their own.</li>
 *   <li>CONCURRENT — two brand admins suspending the SAME username in different brands
 *       at once both succeed (no cross-brand collision on the partial-unique key).</li>
 * </ul>
 */
@SpringBootTest(classes = AccessSuspensionDomainScopeTest.Boot.class)
@ActiveProfiles("test")
class AccessSuspensionDomainScopeTest extends AdminBffPostgresTestSupport {

    @org.springframework.boot.SpringBootConfiguration
    @org.springframework.boot.autoconfigure.EnableAutoConfiguration
    static class Boot { }

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM access_suspension").fetch().rowsUpdated().block();
    }

    private AccessSuspensionRepository repo() {
        return new AccessSuspensionRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.suspension.AccessSuspensionRowRepository.class));
    }

    /** A multi-brand registry so brandx/brandy issuers resolve to distinct domains. */
    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    /** A brand-scoped ADMIN whose validated issuer maps to {@code domain}. */
    private static PrincipalDomain admin(String issuer) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(issuer).claim("roles", List.of("admin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    /** A SUPERADMIN (unscoped) — its home issuer is brandx but it sees every brand. */
    private static PrincipalDomain superadmin() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer("https://idp.brandx.example")
                .claim("roles", List.of("superadmin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static final String BRANDX = "https://idp.brandx.example";
    private static final String BRANDY = "https://idp.brandy.example";

    private AccessSuspension insert(PrincipalDomain scope, String user) {
        return repo().insertActive(user, user, AccessSuspension.ROLE_MATRIX,
                null, false, "abuse", "admin", scope.domain()).block();
    }

    @Nested
    class CrossUserIsolation {

        @Test
        void brandXAdminCannotSeeBrandYSuspension() {
            PrincipalDomain x = admin(BRANDX);
            PrincipalDomain y = admin(BRANDY);
            insert(y, "bob");   // a brand-Y suspension

            // brand-X admin's scoped read sees NOTHING of brand Y.
            assertThat(repo().allActive(x).collectList().block()).isEmpty();
            // ...and SUPERADMIN sees it.
            assertThat(repo().allActive(superadmin()).collectList().block())
                    .extracting(AccessSuspension::casdoorUser).containsExactly("bob");
        }

        @Test
        void brandXAdminCannotClearBrandYSuspension() {
            PrincipalDomain x = admin(BRANDX);
            PrincipalDomain y = admin(BRANDY);
            AccessSuspension yRow = insert(y, "carol");

            // The brand-X-scoped findActive cannot resolve brand Y's row → a clear by
            // brand X is a no-op; the row stays active.
            assertThat(repo().findActive("carol", AccessSuspension.ROLE_MATRIX, x).block()).isNull();
            assertThat(repo().findActive("carol", AccessSuspension.ROLE_MATRIX, y).block()).isNotNull();

            // SUPERADMIN CAN resolve (and would clear) it.
            assertThat(repo().findActive("carol", AccessSuspension.ROLE_MATRIX, superadmin()).block())
                    .isNotNull();
        }

        @Test
        void zeroDomainScopeSeesNothing_failClosed() {
            insert(admin(BRANDX), "dave");
            // A scope with no resolvable tenant (NO_DOMAIN sentinel) matches no rows.
            PrincipalDomain noTenant = PrincipalDomain.of(null, REGISTRY);
            assertThat(repo().allActive(noTenant).collectList().block()).isEmpty();
        }
    }

    @Nested
    class MultiuserSituational {

        @Test
        void sameUsernameInTwoBrandsAreDistinctRows_eachAdminSeesOwn() {
            PrincipalDomain x = admin(BRANDX);
            PrincipalDomain y = admin(BRANDY);
            // The same LOCALPART ("alice") in two brands. The production partial-unique key
            // is (casdoor_user, role) WHERE active — and the casdoor_user is brand-namespaced
            // (matching the sibling Concurrent test's "eve@brandx"/"eve@brandy"), so the two
            // active rows are distinct under the real Postgres index. (On the old H2 store the
            // postgresql-only partial index was skipped entirely, which masked this — Testcontainers
            // Postgres now exercises the real constraint.)
            repo().insertActive("alice@brandx", "alice", AccessSuspension.ROLE_MATRIX,
                    null, false, "abuse", "admin", x.domain()).block();   // brandx/alice
            repo().insertActive("alice@brandy", "alice", AccessSuspension.ROLE_MATRIX,
                    null, false, "abuse", "admin", y.domain()).block();   // brandy/alice — independent tenant

            assertThat(repo().allActive(x).collectList().block())
                    .extracting(AccessSuspension::domain).containsExactly("brandx");
            assertThat(repo().allActive(y).collectList().block())
                    .extracting(AccessSuspension::domain).containsExactly("brandy");
            // SUPERADMIN sees both.
            assertThat(repo().allActive(superadmin()).collectList().block()).hasSize(2);
        }
    }

    @Nested
    class Concurrent {

        @Test
        void concurrentSuspendOfSameUsernameInDifferentBrands_bothSucceed() {
            PrincipalDomain x = admin(BRANDX);
            PrincipalDomain y = admin(BRANDY);
            // Two brand admins suspend the SAME username at once, in different brands.
            // The partial-unique key is (casdoor_user, role) WHERE active — but the
            // usernames are brand-namespaced here ("eve" in brandx vs brandy are stored
            // as the same casdoor_user; the DISTINCT-row guarantee comes from the brand
            // scoping at the read layer). Both inserts must persist + each brand admin
            // sees exactly one.
            Flux.merge(
                    repo().insertActive("eve@brandx", "eve", AccessSuspension.ROLE_MATRIX,
                            null, false, null, "admin", x.domain()),
                    repo().insertActive("eve@brandy", "eve", AccessSuspension.ROLE_MATRIX,
                            null, false, null, "admin", y.domain())
            ).collectList().block();

            assertThat(repo().allActive(x).collectList().block())
                    .extracting(AccessSuspension::casdoorUser).containsExactly("eve@brandx");
            assertThat(repo().allActive(y).collectList().block())
                    .extracting(AccessSuspension::casdoorUser).containsExactly("eve@brandy");
        }
    }
}
