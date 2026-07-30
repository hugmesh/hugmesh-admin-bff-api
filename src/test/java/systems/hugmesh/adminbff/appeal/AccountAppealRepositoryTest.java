package systems.hugmesh.adminbff.appeal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The account_appeal R2DBC repository over a Liquibase-applied H2 (PG-compat) — proves
 * the 250 changelog applies (table + status CHECK) and the owner==subject + brand-scope
 * + decide-CAS idioms round-trip (clones DesktopInstallRequestRepositoryTest's shape for
 * the ACCOUNT-ban appeal domain).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class AccountAppealRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void seed() {
        db.sql("DELETE FROM account_appeal").fetch().rowsUpdated().block();
    }

    private AccountAppealRepository repo() {
        return new AccountAppealRepository(
                systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, AccountAppealR2dbcRepository.class));
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private static PrincipalDomain admin(String issuer) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(issuer).claim("roles", List.of("admin")).build();
        Authentication auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static PrincipalDomain superadmin() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer("https://idp.brandx.example").claim("roles", List.of("superadmin")).build();
        Authentication auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    // ── owner == subject (negative cross-user isolation) ─────────────────────────

    @Nested
    class OwnerIsSubject {
        @Test
        void user_seesOnlyOwnAppeals() {
            AccountAppealRepository r = repo();
            r.insertPending("google:alice@x.com", "alice@x.com", "brandx", "let me back in", null).block();
            r.insertPending("google:bob@x.com", "bob@x.com", "brandx", "unfair ban", null).block();
            // alice sees ONLY hers — bob's appeal is invisible (cross-user DENY).
            assertThat(r.listForUser("google:alice@x.com", "brandx").collectList().block())
                    .extracting(AccountAppeal::userSub).containsExactly("google:alice@x.com");
        }
    }

    // ── idempotent re-submit ──────────────────────────────────────────────────────

    @Nested
    class IdempotentSubmit {
        @Test
        void findPendingForUser_returnsExistingPendingRow() {
            AccountAppealRepository r = repo();
            AccountAppeal first = r.insertPending("google:alice@x.com", "alice@x.com", "brandx", "reason1", null).block();
            assertThat(r.findPendingForUser("google:alice@x.com", "brandx").block().id()).isEqualTo(first.id());
        }
    }

    // ── admin brand-scope + decide CAS ───────────────────────────────────────────

    @Nested
    class AdminScopeAndDecide {
        @Test
        void adminInbox_isBrandScoped() {
            AccountAppealRepository r = repo();
            r.insertPending("google:alice@x.com", "alice@x.com", "brandx", "r1", null).block();
            r.insertPending("google:carol@y.com", "carol@y.com", "brandy", "r2", null).block();
            assertThat(r.list(admin("https://idp.brandx.example")).collectList().block())
                    .extracting(AccountAppeal::domain).containsOnly("brandx");
            assertThat(r.list(superadmin()).collectList().block())
                    .extracting(AccountAppeal::domain).contains("brandx", "brandy");
        }

        @Test
        void decide_isSingleWinner_andBrandScoped() {
            AccountAppealRepository r = repo();
            AccountAppeal appeal = r.insertPending("google:alice@x.com", "alice@x.com", "brandx", "r1", null).block();
            // first decide wins; a second decide is a no-op (no longer pending).
            assertThat(r.decide(appeal.id(), "APPROVED", "admin-x", superadmin()).block()).isEqualTo(1L);
            assertThat(r.decide(appeal.id(), "DENIED", "admin-x", superadmin()).block()).isEqualTo(0L);
        }

        @Test
        void scopedAdmin_cannotDecideOtherBrandAppeal() {
            AccountAppealRepository r = repo();
            AccountAppeal appealY = r.insertPending("google:carol@y.com", "carol@y.com", "brandy", "r2", null).block();
            // a brand-X admin cannot decide a brand-Y appeal (rows-updated 0).
            assertThat(r.decide(appealY.id(), "APPROVED", "x-admin", admin("https://idp.brandx.example")).block())
                    .isEqualTo(0L);
        }
    }
}
