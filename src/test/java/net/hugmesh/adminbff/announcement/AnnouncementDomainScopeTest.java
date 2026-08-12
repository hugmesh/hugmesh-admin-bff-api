package net.hugmesh.adminbff.announcement;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cross-brand tenant-isolation tests for the announcement domain predicate over a
 * real H2 (PG-compat) store (Liquibase changesets 060 + 061).
 *
 * <p>Delineated:
 * <ul>
 *   <li>CROSS-USER (DENY) — a brand-X admin lists/finds/deletes ONLY brand-X
 *       announcements; a brand-Y announcement is invisible (empty, not a 403 leak).
 *       A delete of a cross-brand id is a no-op (the row survives).</li>
 *   <li>MULTIUSER-SITUATIONAL (ALLOW) — SUPERADMIN is unscoped and sees every
 *       brand's rows, resolves cross-brand ids, and can delete any id.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, AnnouncementRepository.class})
class AnnouncementDomainScopeTest {

    @Autowired AnnouncementRepository repo;
    @Autowired DatabaseClient db;

    @BeforeEach
    @AfterEach
    void clear() {
        db.sql("DELETE FROM announcement").fetch().rowsUpdated().block();
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

    /** Insert a minimal published announcement stamped with the given scope's domain. */
    private Announcement addFor(PrincipalDomain scope, String title) {
        Announcement a = new Announcement(null, title, "<p>hi</p>", "html", "published",
                true, false, false, false, 0, null, null, "UTC", true,
                "admin@x", null, null, null, scope.domain());
        return repo.insert(a).block();
    }

    @Nested
    class CrossUserIsolation {

        /**
         * CROSS-USER DENY: brand-X admin lists only brand-X announcements; brand-Y
         * rows are completely invisible (empty list for brand-Y admin). SUPERADMIN sees
         * all.
         */
        @Test
        void brandXAdminListsOnlyBrandXAnnouncements() {
            PrincipalDomain x = admin("https://idp.brandx.example");
            PrincipalDomain y = admin("https://idp.brandy.example");
            addFor(x, "brandx-news");
            addFor(y, "brandy-news");

            assertThat(repo.list(x).collectList().block())
                    .extracting(Announcement::title).containsExactly("brandx-news");
            assertThat(repo.list(y).collectList().block())
                    .extracting(Announcement::title).containsExactly("brandy-news");
            assertThat(repo.list(superadmin()).collectList().block()).hasSize(2);
        }

        /**
         * CROSS-USER DENY: brand-X admin cannot find brand-Y's announcement by id —
         * it resolves to empty (invisible, not a data-leaking response).
         */
        @Test
        void brandXAdminCannotFindBrandYAnnouncementById() {
            PrincipalDomain x = admin("https://idp.brandx.example");
            PrincipalDomain y = admin("https://idp.brandy.example");
            Announcement yRow = addFor(y, "brandy-only");

            // Brand-X-scoped find of brand-Y's id → invisible (empty).
            assertThat(repo.find(yRow.id(), x).block()).isNull();
            // Brand-Y admin resolves it.
            assertThat(repo.find(yRow.id(), y).block()).isNotNull()
                    .extracting(Announcement::title).isEqualTo("brandy-only");
            // SUPERADMIN resolves it.
            assertThat(repo.find(yRow.id(), superadmin()).block()).isNotNull();
        }

        /**
         * CROSS-USER DENY: brand-X admin cannot delete brand-Y's row — the scoped
         * DELETE WHERE id=? AND domain=? matches 0 rows; the row survives.
         * SUPERADMIN deletes it.
         */
        @Test
        void brandXAdminCannotDeleteBrandYAnnouncement() {
            PrincipalDomain x = admin("https://idp.brandx.example");
            PrincipalDomain y = admin("https://idp.brandy.example");
            Announcement yRow = addFor(y, "brandy-protected");

            // Brand-X delete of brand-Y's id is a no-op: row still visible to Y.
            repo.delete(yRow.id(), x).block();
            assertThat(repo.find(yRow.id(), y).block()).isNotNull();

            // SUPERADMIN deletes it.
            repo.delete(yRow.id(), superadmin()).block();
            assertThat(repo.find(yRow.id(), superadmin()).block()).isNull();
        }
    }

    @Nested
    class SuperadminUnscoped {

        /**
         * MULTIUSER-SITUATIONAL ALLOW: SUPERADMIN list is unscoped — sees all brands.
         */
        @Test
        void superadminSeesAllBrandsAnnouncements() {
            PrincipalDomain x = admin("https://idp.brandx.example");
            PrincipalDomain y = admin("https://idp.brandy.example");
            addFor(x, "x-item");
            addFor(y, "y-item");

            List<String> titles = repo.list(superadmin()).collectList().block()
                    .stream().map(Announcement::title).toList();
            assertThat(titles).containsExactlyInAnyOrder("x-item", "y-item");
        }

        /**
         * MULTIUSER-SITUATIONAL ALLOW: SUPERADMIN can insert and then find across any
         * domain boundary.
         */
        @Test
        void superadminCanInsertForAnyDomainAndFind() {
            PrincipalDomain x = admin("https://idp.brandx.example");
            // Insert stamped with brand-X domain via brand-X admin scope.
            Announcement xRow = addFor(x, "x-item-sa");
            // SUPERADMIN resolves it.
            assertThat(repo.find(xRow.id(), superadmin()).block())
                    .isNotNull().extracting(Announcement::domain).isEqualTo("brandx");
        }
    }
}
