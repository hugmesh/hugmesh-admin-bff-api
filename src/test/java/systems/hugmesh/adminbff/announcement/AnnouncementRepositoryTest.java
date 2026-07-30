package systems.hugmesh.adminbff.announcement;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates the announcement R2DBC SQL against H2 (PostgreSQL-compat) with the
 * Liquibase-applied changeset 060+061 — insert → find → list, update, akkoma_ref
 * management, delete, and (crucially) the active-window + per-surface target query
 * correctness. Domain isolation tests live in AnnouncementDomainScopeTest.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, AnnouncementRepository.class})
class AnnouncementRepositoryTest {

    @Autowired AnnouncementRepository repo;

    /** SUPERADMIN scope (unscoped) — used for existing round-trip tests that are not
     *  testing isolation (those live in AnnouncementDomainScopeTest). */
    private static final PrincipalDomain SUPER = superadminScope();

    private static PrincipalDomain superadminScope() {
        org.springframework.security.oauth2.jwt.Jwt jwt =
                org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t")
                        .header("alg", "none")
                        .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                        .subject("u").issuer("https://idp.example")
                        .claim("roles", List.of("superadmin")).build();
        var auth = new org.springframework.security.oauth2.server.resource.authentication
                .JwtAuthenticationToken(jwt,
                List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, new systems.hugmesh.commons.security.DomainRegistry("", ""));
    }

    private static Announcement announcement(String title, String state,
                                             boolean home, boolean login, boolean akkoma, boolean forum,
                                             Instant startsAt, Instant endsAt, int priority) {
        return new Announcement(null, title, "<p>hi</p>", "html", state,
                home, login, akkoma, forum, priority, startsAt, endsAt, "UTC", true,
                "admin@x", null, null, null, "default");
    }

    @Test
    void insertFindUpdateDelete_roundTrip() {
        Announcement saved = repo.insert(announcement("T1", "draft",
                true, false, false, false, null, null, 5)).block();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.state()).isEqualTo("draft");
        assertThat(saved.targetHome()).isTrue();
        assertThat(saved.dismissible()).isTrue();
        assertThat(saved.createdAt()).isNotNull();
        assertThat(saved.updatedAt()).isNotNull();

        Announcement found = repo.find(saved.id(), SUPER).block();
        assertThat(found.title()).isEqualTo("T1");
        assertThat(found.timezone()).isEqualTo("UTC");

        // Update flips state to published + adds the login surface.
        Announcement edit = new Announcement(saved.id(), "T1-edited", "<p>x</p>", "html", "published",
                true, true, false, false, 9, null, null, "UTC", false, "admin@x", null, null, null, "default");
        Announcement updated = repo.update(saved.id(), edit).block();
        assertThat(updated.title()).isEqualTo("T1-edited");
        assertThat(updated.state()).isEqualTo("published");
        assertThat(updated.targetLogin()).isTrue();
        assertThat(updated.priority()).isEqualTo(9);
        assertThat(updated.dismissible()).isFalse();

        assertThat(repo.list(SUPER).collectList().block()).extracting(Announcement::id).contains(saved.id());

        repo.delete(saved.id(), SUPER).block();
        assertThat(repo.find(saved.id(), SUPER).block()).isNull();
    }

    @Test
    void setAkkomaRef_setsAndClears() {
        Announcement saved = repo.insert(announcement("Akk", "published",
                false, false, true, false, null, null, 0)).block();
        assertThat(saved.akkomaRef()).isNull();

        repo.setAkkomaRef(saved.id(), "akk-123").block();
        assertThat(repo.find(saved.id(), SUPER).block().akkomaRef()).isEqualTo("akk-123");

        repo.setAkkomaRef(saved.id(), null).block();
        assertThat(repo.find(saved.id(), SUPER).block().akkomaRef()).isNull();
    }

    @Test
    void activeForHome_onlyPublishedInWindowTargeted_orderedByPriority() {
        // The H2 store is shared across this class's test methods, so assert only on
        // the rows THIS test created (unique "H_" titles) — not on the whole table.
        Instant now = Instant.now();
        // Active: published, home, open window, priority 1 and 7.
        repo.insert(announcement("H_lo", "published", true, false, false, false, null, null, 1)).block();
        repo.insert(announcement("H_hi", "published", true, false, false, false,
                now.minus(1, ChronoUnit.HOURS), now.plus(1, ChronoUnit.HOURS), 7)).block();
        // Inactive: draft / not-home / future / expired.
        repo.insert(announcement("H_draft", "draft", true, false, false, false, null, null, 9)).block();
        repo.insert(announcement("H_loginonly", "published", false, true, false, false, null, null, 9)).block();
        repo.insert(announcement("H_future", "published", true, false, false, false,
                now.plus(1, ChronoUnit.HOURS), null, 9)).block();
        repo.insert(announcement("H_expired", "published", true, false, false, false,
                now.minus(2, ChronoUnit.HOURS), now.minus(1, ChronoUnit.HOURS), 9)).block();

        List<String> mine = repo.activeForHome(now).collectList().block().stream()
                .map(Announcement::title).filter(t -> t.startsWith("H_")).toList();
        // priority DESC: H_hi (7) before H_lo (1); the inactive H_* rows are excluded.
        assertThat(mine).containsExactly("H_hi", "H_lo");
    }

    @Test
    void activeForLogin_andForum_filterByTheirOwnFlag() {
        Instant now = Instant.now();
        repo.insert(announcement("LF_login", "published", false, true, false, false, null, null, 0)).block();
        repo.insert(announcement("LF_forum", "published", false, false, false, true, null, null, 0)).block();
        repo.insert(announcement("LF_home", "published", true, false, false, false, null, null, 0)).block();

        List<String> login = repo.activeForLogin(now).collectList().block().stream()
                .map(Announcement::title).filter(t -> t.startsWith("LF_")).toList();
        List<String> forum = repo.activeForForum(now).collectList().block().stream()
                .map(Announcement::title).filter(t -> t.startsWith("LF_")).toList();
        assertThat(login).containsExactly("LF_login");
        assertThat(forum).containsExactly("LF_forum");
    }

    @Test
    void expiredWithAkkomaRef_findsStalePosts() {
        Instant now = Instant.now();
        // Live akkoma (published, akkoma, open) WITH a ref → NOT stale.
        Announcement live = repo.insert(announcement("live", "published",
                false, false, true, false, null, null, 0)).block();
        repo.setAkkomaRef(live.id(), "akk-live").block();
        // Expired but still carries a ref → stale.
        Announcement expired = repo.insert(announcement("exp", "published",
                false, false, true, false, now.minus(2, ChronoUnit.HOURS), now.minus(1, ChronoUnit.HOURS), 0)).block();
        repo.setAkkomaRef(expired.id(), "akk-exp").block();
        // Unpublished but still carries a ref → stale.
        Announcement unpub = repo.insert(announcement("unpub", "draft",
                false, false, true, false, null, null, 0)).block();
        repo.setAkkomaRef(unpub.id(), "akk-unpub").block();

        List<String> stale = repo.expiredWithAkkomaRef(now).collectList().block()
                .stream().map(Announcement::id).toList();
        assertThat(stale).contains(expired.id(), unpub.id()).doesNotContain(live.id());
    }
}
