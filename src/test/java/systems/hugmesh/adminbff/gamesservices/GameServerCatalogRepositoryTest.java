package systems.hugmesh.adminbff.gamesservices;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The game_server_catalog R2DBC repository over a Liquibase-applied H2 (PG-compat) — proves
 * the 090 changelog applies (table + slug UNIQUE + digest-pin CHECK) and that the curated
 * FOSS seed loaded. Uses {@code @DataR2dbcTest} (like {@code DomainRegistryRepositoryTest}).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class GameServerCatalogRepositoryTest {

    @Autowired DatabaseClient db;

    private GameServerCatalogRepository repo() {
        return new GameServerCatalogRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.gamesservices.GameServerCatalogR2dbcRepository.class));
    }

    private static final String PINNED =
            "ghcr.io/hugmesh-systems/games/test@sha256:"
            + "1111111111111111111111111111111111111111111111111111111111111111";

    private static GameServerCatalogEntry draft(String slug, boolean enabled) {
        return new GameServerCatalogEntry(null, slug, "Test " + slug, PINNED,
                "GPL-3.0-or-later", "udp", 30000, 8080, "a test server", enabled,
                null, null, null);
    }

    @Test
    void seed_loaded_eightCuratedFossServers_allDigestPinnedWithSpdx() {
        var all = repo().findAll().collectList().block();
        assertThat(all).hasSizeGreaterThanOrEqualTo(8);
        assertThat(all).extracting(GameServerCatalogEntry::slug)
                .contains("minetest", "veloren", "xonotic", "openarena",
                        "teeworlds", "mindustry", "zeroad", "supertuxkart");
        // Every seeded row is digest-pinned and carries a non-blank SPDX license.
        assertThat(all).allSatisfy(e -> {
            assertThat(ImageRef.isDigestPinned(e.imageRef()))
                    .as("seed %s image_ref is digest-pinned", e.slug()).isTrue();
            assertThat(e.licenseSpdx()).as("seed %s SPDX", e.slug()).isNotBlank();
        });
    }

    @Test
    void insert_thenFindBySlug_roundTripsAndStampsSubject() {
        GameServerCatalogRepository repo = repo();
        GameServerCatalogEntry saved = repo.insert(draft("freeciv", true), "super@infra").block();
        assertThat(saved).isNotNull();
        assertThat(saved.id()).isNotBlank();
        assertThat(saved.createdBySubject()).isEqualTo("super@infra");

        StepVerifier.create(repo.findBySlug("freeciv"))
                .assertNext(found -> {
                    assertThat(found.displayName()).isEqualTo("Test freeciv");
                    assertThat(found.imageRef()).isEqualTo(PINNED);
                    assertThat(found.consolePort()).isEqualTo(8080);
                    assertThat(found.containerPort()).isEqualTo(30000);
                    assertThat(found.id()).isEqualTo(saved.id());
                })
                .verifyComplete();
    }

    @Test
    void uniqueSlug_rejectsDuplicateInsert() {
        GameServerCatalogRepository repo = repo();
        repo.insert(draft("dup", true), "super@infra").block();
        StepVerifier.create(repo.insert(draft("dup", true), "other@infra"))
                .expectError()
                .verify();
    }

    @Test
    void digestPinCheck_rejectsTagOnlyImageRef() {
        // DB-level defence-in-depth: a tag-only ref violates ck_game_server_catalog_digest_pin.
        GameServerCatalogEntry tagOnly = new GameServerCatalogEntry(null, "badpin",
                "Bad Pin", "ghcr.io/x/y:latest", "MIT", "udp", 1, null, null, true,
                null, null, null);
        StepVerifier.create(repo().insert(tagOnly, "super@infra"))
                .expectError()
                .verify();
    }

    @Test
    void findEnabled_excludesSoftDisabled() {
        GameServerCatalogRepository repo = repo();
        repo.insert(draft("on-server", true), "super@infra").block();
        repo.insert(draft("off-server", false), "super@infra").block();

        var enabledSlugs = repo.findEnabled().collectList().block();
        assertThat(enabledSlugs).extracting(GameServerCatalogEntry::slug).contains("on-server");
        assertThat(enabledSlugs).extracting(GameServerCatalogEntry::slug).doesNotContain("off-server");
    }

    @Test
    void update_changesMutableFields_butNotIdOrSlug_andSoftDisables() {
        GameServerCatalogRepository repo = repo();
        GameServerCatalogEntry original = repo.insert(draft("upd", true), "creator@infra").block();

        String newPin = "ghcr.io/x/y@sha256:"
                + "2222222222222222222222222222222222222222222222222222222222222222";
        GameServerCatalogEntry merged = new GameServerCatalogEntry(
                original.id(), "upd", "Renamed", newPin, "Apache-2.0", "tcp", 9999, null,
                "new summary", false, original.createdAt(), original.createdBySubject(),
                original.updatedAt());

        GameServerCatalogEntry updated = repo.update(merged).block();
        assertThat(updated).isNotNull();
        assertThat(updated.displayName()).isEqualTo("Renamed");
        assertThat(updated.imageRef()).isEqualTo(newPin);
        assertThat(updated.protocol()).isEqualTo("tcp");
        assertThat(updated.enabled()).isFalse();           // soft-disable
        assertThat(updated.id()).isEqualTo(original.id()); // PK unchanged
        assertThat(updated.slug()).isEqualTo("upd");        // natural key unchanged
        assertThat(updated.createdBySubject()).isEqualTo("creator@infra");
    }

    @Test
    void update_unknownSlug_isEmpty() {
        StepVerifier.create(repo().update(draft("ghost", true)))
                .verifyComplete();
    }
}
