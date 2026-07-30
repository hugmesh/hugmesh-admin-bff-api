package systems.hugmesh.adminbff.routeaccess;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates the reactive R2DBC SQL against H2 (PostgreSQL-compat mode) with the
 * Liquibase-applied schema (TestDatabaseConfig runs the production changelog over
 * the same H2 mem DB the DatabaseClient accesses via R2DBC). NON_KEYWORDS
 * neutralises the role/allow column names so the same DDL/queries work here and
 * on real Postgres.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, RouteAccessRepository.class})
class RouteAccessRepositoryTest {

    @Autowired RouteAccessRepository repo;

    @Test
    void addListDelete_roundTrip() {
        assertThat(repo.list().collectList().block()).isEmpty();

        RouteRule saved = repo.add(new RouteRule(null, "hugmesh-be-gateway", "/api/admin/**", "ROLE_ADMIN", null, true, "default")).block();
        assertThat(saved.id()).isNotBlank();

        List<RouteRule> rules = repo.list().collectList().block();
        assertThat(rules).hasSize(1);
        assertThat(rules.get(0).gateway()).isEqualTo("hugmesh-be-gateway");
        assertThat(rules.get(0).urlPattern()).isEqualTo("/api/admin/**");
        assertThat(rules.get(0).role()).isEqualTo("ROLE_ADMIN");
        assertThat(rules.get(0).allow()).isTrue();

        repo.delete(saved.id()).block();
        assertThat(repo.list().collectList().block()).isEmpty();
    }

    @Test
    void userScopedDenyRule_persists() {
        RouteRule saved = repo.add(new RouteRule(null, "hugmesh-fe-gateway", "/admin/**", "ROLE_ADMIN", "alice", false, "default")).block();
        RouteRule got = repo.list().collectList().block().stream()
                .filter(r -> r.id().equals(saved.id())).findFirst().orElseThrow();
        assertThat(got.casdoorUser()).isEqualTo("alice");
        assertThat(got.allow()).isFalse();
        repo.delete(saved.id()).block();
    }

    /** The band-181 mfa_required column round-trips through the entity/repository: an
     *  explicit mfaRequired=true is written and read back true. */
    @Test
    void mfaRequiredTrue_roundTrips() {
        RouteRule saved = repo.add(new RouteRule(
                null, "hugmesh-be-gateway", "/api/sudo/**", "ROLE_ADMIN", null, true, "default", true)).block();
        assertThat(saved.mfaRequired()).isTrue();

        RouteRule got = repo.list().collectList().block().stream()
                .filter(r -> r.id().equals(saved.id())).findFirst().orElseThrow();
        assertThat(got.mfaRequired()).isTrue();
        repo.delete(saved.id()).block();
    }

    /** Omitting mfaRequired (the 7-arg back-compat constructor) lands the DB DEFAULT false,
     *  proving the dark/inert default — byte-identical to pre-trio behaviour. */
    @Test
    void mfaRequiredOmitted_defaultsFalse() {
        RouteRule saved = repo.add(new RouteRule(
                null, "hugmesh-be-gateway", "/api/public/**", "ROLE_USER", null, true, "default")).block();
        assertThat(saved.mfaRequired()).isFalse();

        RouteRule got = repo.list().collectList().block().stream()
                .filter(r -> r.id().equals(saved.id())).findFirst().orElseThrow();
        assertThat(got.mfaRequired()).isFalse();
        repo.delete(saved.id()).block();
    }
}
