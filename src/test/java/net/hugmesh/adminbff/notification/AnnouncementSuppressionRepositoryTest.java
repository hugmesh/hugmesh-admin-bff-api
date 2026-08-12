package net.hugmesh.adminbff.notification;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The announcement_suppressed UPSERT store over a Liquibase-applied H2 (PG-compat) —
 * proves the 062 changelog applies and the per-domain toggle round-trips (absent row =
 * not suppressed; the portable update-then-insert upsert flips and preserves the
 * natural key). Uses {@code @DataR2dbcTest} (auto-finds the app config) rather than a
 * nested @SpringBootConfiguration so the WebFlux slice tests in this package don't trip
 * over multiple config classes.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
class AnnouncementSuppressionRepositoryTest {

    @Autowired DatabaseClient db;

    private AnnouncementSuppressionRepository repo() {
        return new AnnouncementSuppressionRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.AnnouncementSuppressionR2dbcRepository.class));
    }

    @Test
    void absentRow_isNotSuppressed() {
        assertThat(repo().isSuppressed("never-touched-domain").block()).isFalse();
    }

    @Test
    void setSuppressed_upsertsAndToggles_perDomain() {
        AnnouncementSuppressionRepository repo = repo();
        // First toggle inserts.
        assertThat(repo.setSuppressed("brandz", true, "admin-a").block()).isTrue();
        assertThat(repo.isSuppressed("brandz").block()).isTrue();
        // Second toggle updates the SAME row (no PK violation).
        assertThat(repo.setSuppressed("brandz", false, "admin-b").block()).isFalse();
        assertThat(repo.isSuppressed("brandz").block()).isFalse();
        // A different domain is independent.
        assertThat(repo.isSuppressed("brandz2").block()).isFalse();
    }
}
