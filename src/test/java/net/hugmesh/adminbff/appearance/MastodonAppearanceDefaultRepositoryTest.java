package net.hugmesh.adminbff.appearance;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates the {@code mastodon_appearance_default} R2DBC upsert/find SQL against the
 * real Liquibase-applied changeset 240: insert-if-absent, update-if-present, and
 * domain isolation (the composite PK is (domain, pref_key)).
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, MastodonAppearanceDefaultRepository.class})
class MastodonAppearanceDefaultRepositoryTest {

    @Autowired MastodonAppearanceDefaultRepository repo;

    @Test
    void upsert_insertsWhenAbsent() {
        repo.upsert("brandx", "theme", "mono", "admin@x").block();
        Map<String, String> view = repo.findAll("brandx").block();
        assertThat(view).containsEntry("theme", "mono");
    }

    @Test
    void upsert_updatesWhenPresent() {
        repo.upsert("brandy", "theme", "mono", "admin@x").block();
        repo.upsert("brandy", "theme", "pastel-sky", "admin@x").block();
        Map<String, String> view = repo.findAll("brandy").block();
        assertThat(view).containsEntry("theme", "pastel-sky");
        assertThat(view).hasSize(1); // no duplicate row for the same (domain, key)
    }

    @Test
    void findAll_emptyForUnconfiguredDomain() {
        Map<String, String> view = repo.findAll("never-configured-brand").block();
        assertThat(view).isEmpty();
    }

    @Test
    void domainIsolation_brandXUpsertDoesNotAffectBrandZ() {
        repo.upsert("brandz1", "theme", "mono", "admin@x").block();
        Map<String, String> otherBrand = repo.findAll("brandz2").block();
        assertThat(otherBrand).isEmpty();
    }
}
