package systems.hugmesh.adminbff.routeaccess;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tenant-isolation tests for the gateway_route_access DOMAIN predicate over a REAL
 * H2 (PG-compat) store. Delineated:
 * <ul>
 *   <li>CROSS-USER — a brand-X admin lists/deletes ONLY brand-X rules; a brand-Y rule
 *       is invisible and a delete-by-id of it is a no-op (its row survives).</li>
 *   <li>MULTIUSER-SITUATIONAL — SUPERADMIN sees + deletes every brand's rule.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, RouteAccessRepository.class})
class RouteAccessDomainScopeTest {

    @Autowired RouteAccessRepository repo;
    @Autowired DatabaseClient db;

    // This @DataR2dbcTest shares its cached context (and H2 store) with
    // RouteAccessRepositoryTest. Clean the table around each test so neither leaks
    // rows into the other's empty-store assumptions.
    @org.junit.jupiter.api.BeforeEach
    @org.junit.jupiter.api.AfterEach
    void clear() {
        db.sql("DELETE FROM gateway_route_access").fetch().rowsUpdated().block();
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private static PrincipalDomain admin(String issuer) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(issuer).claim("roles", List.of("admin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static PrincipalDomain superadmin() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer("https://idp.brandx.example")
                .claim("roles", List.of("superadmin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private RouteRule addFor(PrincipalDomain scope, String gateway) {
        return repo.add(new RouteRule(null, gateway, "/api/**", "ROLE_USER", null, true, scope.domain()))
                .block();
    }

    @Nested
    class CrossUserIsolation {

        @Test
        void brandXAdminListsOnlyBrandXRules() {
            PrincipalDomain x = admin("https://idp.brandx.example");
            PrincipalDomain y = admin("https://idp.brandy.example");
            addFor(x, "brandx-be-gateway");
            addFor(y, "brandy-be-gateway");

            assertThat(repo.list(x).collectList().block())
                    .extracting(RouteRule::gateway).containsExactly("brandx-be-gateway");
            assertThat(repo.list(y).collectList().block())
                    .extracting(RouteRule::gateway).containsExactly("brandy-be-gateway");
            assertThat(repo.list(superadmin()).collectList().block()).hasSize(2);
        }

        @Test
        void brandXAdminCannotDeleteBrandYRule() {
            PrincipalDomain x = admin("https://idp.brandx.example");
            PrincipalDomain y = admin("https://idp.brandy.example");
            RouteRule yRule = addFor(y, "brandy-be-gateway");

            // brand-X-scoped delete of brand Y's id removes 0 rows; the row survives.
            assertThat(repo.delete(yRule.id(), x).block()).isEqualTo(0L);
            assertThat(repo.list(y).collectList().block()).extracting(RouteRule::id)
                    .containsExactly(yRule.id());

            // SUPERADMIN deletes it.
            assertThat(repo.delete(yRule.id(), superadmin()).block()).isEqualTo(1L);
            assertThat(repo.list(superadmin()).collectList().block()).isEmpty();
        }
    }
}
