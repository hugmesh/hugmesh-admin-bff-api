package net.hugmesh.adminbff.domainregistry;

import io.r2dbc.spi.ConnectionFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.reactive.TransactionalOperator;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * DECISION 85c = D (hugmesh-generator#527): on its first start the admin-bff imports the build-time
 * domain list, and the allocator then treats those MCS slots as taken. Over the real
 * Liquibase-applied Postgres, with a real {@link TransactionalOperator}.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DomainRegistryFirstStartImporterTest {

    @Autowired DatabaseClient db;
    @Autowired ConnectionFactory connectionFactory;

    @TempDir Path dir;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM domain_registry").fetch().rowsUpdated().block();
    }

    private DomainRegistryRepository repo() {
        return new DomainRegistryRepository(R2dbcRepos.of(db, DomainRegistryRowRepository.class));
    }

    private DomainRegistryFirstStartImporter importer(String path) {
        return new DomainRegistryFirstStartImporter(repo(),
                TransactionalOperator.create(new R2dbcTransactionManager(connectionFactory)), path);
    }

    private Path file(String json) throws IOException {
        Path p = dir.resolve("provision.json");
        Files.writeString(p, json);
        return p;
    }

    private long count() {
        return db.sql("SELECT count(*) AS n FROM domain_registry").map(r -> r.get("n", Long.class))
                .one().block();
    }

    private static String entry(String domain, String slug, String level, String levelPg) {
        return "{\"clusterDomain\":\"" + domain + "\",\"title\":\"Brand " + slug + "\",\"nsPrefix\":\""
                + slug + "\",\"casdoorOrg\":\"" + slug + "-org\",\"idp\":\"own\",\"selinuxLevel\":\""
                + level + "\",\"selinuxLevelPg\":\"" + levelPg + "\"}";
    }

    /** The provision.json shape (decision 85a = A): an object carrying domains[] among other keys. */
    private static String provision(String... entries) {
        return "{\"version\":1,\"hostname\":\"node-1\",\"domains\":[" + String.join(",", entries) + "]}";
    }

    @Test
    void importsTwoDomains_thenAThirdRegistrationGetsADistinctSlot() throws IOException {
        // Slots 0 and 2 — deliberately NOT the lowest two, so a lowest-free allocator that ignored
        // the imported rows would collide with slot 0 and one that only counted rows would pick 2.
        Path p = file(provision(
                entry("brandb.example", "brandb", "s0:c256", "s0:c257"),
                entry("brandc.example", "brandc", "s0:c260", "s0:c261")));

        assertThat(importer(p.toString()).importIfConfigured()).isEqualTo(2);

        DomainRegistration b = repo().findByClusterDomain("brandb.example").block();
        assertThat(b).isNotNull();
        assertThat(b.nsPrefix()).isEqualTo("brandb");
        assertThat(b.casdoorOrg()).isEqualTo("brandb-org");
        assertThat(b.idp()).isEqualTo(DomainIdp.OWN);
        assertThat(b.brandTitle()).isEqualTo("Brand brandb");
        assertThat(b.selinuxLevel()).isEqualTo("s0:c256");
        assertThat(b.selinuxLevelPg()).isEqualTo("s0:c257");
        assertThat(b.enabled()).isTrue();
        assertThat(b.createdBySubject()).isEqualTo(DomainRegistryFirstStartImporter.IMPORT_SUBJECT);

        DomainRegistration third = new DomainRegistryService(repo()).create(
                new net.hugmesh.adminbff.web.dto.CreateDomainRequest("brandd.example", "brandd",
                        null, null, "brandd", null, null, null, null, null, null), "sa@infra").block();
        assertThat(third.selinuxLevel()).isEqualTo("s0:c258");
        assertThat(third.selinuxLevelPg()).isEqualTo("s0:c259");
        assertThat(List.of(third.selinuxLevel(), third.selinuxLevelPg()))
                .doesNotContain("s0:c256", "s0:c257", "s0:c260", "s0:c261");
    }

    @Test
    void acceptsABareArrayToo() throws IOException {
        Path p = file("[" + entry("brandb.example", "brandb", "s0:c256", "s0:c257") + "]");
        assertThat(importer(p.toString()).importIfConfigured()).isEqualTo(1);
    }

    @Test
    void duplicatePair_refusesTheWholeImport_insertsNothing() throws IOException {
        Path p = file(provision(
                entry("brandb.example", "brandb", "s0:c256", "s0:c257"),
                entry("brandc.example", "brandc", "s0:c256", "s0:c257")));
        assertThatThrownBy(() -> importer(p.toString()).importIfConfigured())
                .isInstanceOf(DomainRegistryFirstStartImporter.ImportRefused.class)
                .hasMessageContaining("duplicates domains[0]");
        assertThat(count()).isZero();
    }

    @Test
    void nonEmptyRegistry_isNeverImportedInto_andTheFileIsNotEvenRead() throws IOException {
        repo().insert(new DomainRegistration(null, "live.example", "live", null, null, "live", null,
                null, true, null, null, null), "sa@infra").block();
        Path good = file(provision(entry("brandb.example", "brandb", "s0:c258", "s0:c259")));
        assertThat(importer(good.toString()).importIfConfigured()).isZero();
        assertThat(count()).isEqualTo(1L);
        // Even an unreadable file cannot block a restart once the registry has rows.
        assertThat(importer(dir.resolve("absent.json").toString()).importIfConfigured()).isZero();
        assertThat(count()).isEqualTo(1L);
    }

    @Test
    void unsetPath_isANoOp() {
        assertThat(importer("").importIfConfigured()).isZero();
        assertThat(importer("   ").importIfConfigured()).isZero();
        assertThat(count()).isZero();
    }

    @Test
    void setPath_missingFile_refuses() {
        assertThatThrownBy(() -> importer(dir.resolve("absent.json").toString()).importIfConfigured())
                .isInstanceOf(DomainRegistryFirstStartImporter.ImportRefused.class);
        assertThat(count()).isZero();
    }

    @Test
    void outOfRangePair_isRefused() throws IOException {
        // The base's forbidden placeholders (docs/DOMAIN-IDP.md:56) and anything under the floor.
        Path p = file(provision(entry("brandb.example", "brandb", "s0:c84", "s0:c85")));
        assertThatThrownBy(() -> importer(p.toString()).importIfConfigured())
                .isInstanceOf(DomainRegistryFirstStartImporter.ImportRefused.class)
                .hasMessageContaining("outside the reserved per-domain range");
        assertThat(count()).isZero();
    }

    @Test
    void pairThatIsNotOneAllocatorSlot_isRefused() throws IOException {
        for (String[] bad : new String[][]{
                {"s0:c257", "s0:c258"},     // odd level: straddles two slots
                {"s0:c256", "s0:c258"},     // pg not level+1
                {"s0:c256", "s0:c256"},     // same category twice
                {"s0:c1023", "s0:c1024"}}) { // pg above the ceiling
            Path p = file(provision(entry("brandb.example", "brandb", bad[0], bad[1])));
            assertThatThrownBy(() -> importer(p.toString()).importIfConfigured())
                    .as(bad[0] + "/" + bad[1])
                    .isInstanceOf(DomainRegistryFirstStartImporter.ImportRefused.class);
        }
        assertThat(count()).isZero();
    }

    @Test
    void missingPair_badSlug_badDomain_duplicateDomainAndSlug_allRefused_reportedTogether()
            throws IOException {
        Path p = file(provision(
                "{\"clusterDomain\":\"brandb.example\",\"nsPrefix\":\"brandb\"}",
                entry("Upper.Example", "brandc", "s0:c260", "s0:c261"),
                entry("brandd.example", "Not_A_Label", "s0:c262", "s0:c263"),
                entry("brande.example", "brande", "s0:c264", "s0:c265"),
                entry("brande.example", "brande", "s0:c266", "s0:c267")));
        assertThatThrownBy(() -> importer(p.toString()).importIfConfigured())
                .isInstanceOf(DomainRegistryFirstStartImporter.ImportRefused.class)
                .hasMessageContaining("domains[0]")
                .hasMessageContaining("domains[1].clusterDomain")
                .hasMessageContaining("domains[2]")
                .hasMessageContaining("clusterDomain 'brande.example' duplicates domains[3]")
                .hasMessageContaining("nsPrefix 'brande' duplicates domains[3]");
        assertThat(count()).isZero();
    }

    @Test
    void notJson_orNoDomainsArray_isRefused() throws IOException {
        Path garbage = file("{not json");
        assertThatThrownBy(() -> importer(garbage.toString()).importIfConfigured())
                .isInstanceOf(DomainRegistryFirstStartImporter.ImportRefused.class);
        Path noList = file("{\"version\":1}");
        assertThatThrownBy(() -> importer(noList.toString()).importIfConfigured())
                .isInstanceOf(DomainRegistryFirstStartImporter.ImportRefused.class);
        assertThat(count()).isZero();
    }

    @Test
    void aDatabaseFailureMidway_rollsBackEverything() {
        // Two drafts that pass nothing through parse(): the second reuses the first's slug, which
        // only the UNIQUE constraint catches. The transaction must leave the registry EMPTY.
        DomainRegistration a = new DomainRegistration(null, "a.example", null, null, null, "same",
                null, null, true, null, null, null, false, false, 0L, "own", "s0:c256", "s0:c257");
        DomainRegistration b = new DomainRegistration(null, "b.example", null, null, null, "same",
                null, null, true, null, null, null, false, false, 0L, "own", "s0:c258", "s0:c259");
        assertThatThrownBy(() -> importer("/unused").importDrafts(List.of(a, b)))
                .isInstanceOf(DomainRegistryFirstStartImporter.ImportRefused.class);
        assertThat(count()).as("the first row must have been rolled back").isZero();
    }

    @Test
    void aPeerReplicaThatImportedTheSameRows_isNotAFailure() {
        DomainRegistration a = new DomainRegistration(null, "a.example", null, null, null, "a",
                null, null, true, null, null, null, false, false, 0L, "own", "s0:c256", "s0:c257");
        repo().insert(a, DomainRegistryFirstStartImporter.IMPORT_SUBJECT).block();   // the peer won
        assertThat(importer("/unused").importDrafts(List.of(a))).isZero();
        assertThat(count()).isEqualTo(1L);
    }

    @Test
    void aPeerRowThatDiffers_stillRefuses() {
        DomainRegistration peer = new DomainRegistration(null, "a.example", null, null, null, "a",
                null, null, true, null, null, null, false, false, 0L, "own", "s0:c258", "s0:c259");
        repo().insert(peer, "someone").block();
        DomainRegistration mine = new DomainRegistration(null, "a.example", null, null, null, "a",
                null, null, true, null, null, null, false, false, 0L, "own", "s0:c256", "s0:c257");
        assertThatThrownBy(() -> importer("/unused").importDrafts(List.of(mine)))
                .isInstanceOf(DomainRegistryFirstStartImporter.ImportRefused.class);
    }
}
