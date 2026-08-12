package net.hugmesh.adminbff.cloudbackup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The backup_destination + backup_artifact R2DBC repositories over a Liquibase-applied H2
 * (PG-compat) — proves the 160/162 changelog applies (tables + CHECKs + UNIQUE + the
 * backup_artifact -> backup_set FK) and the upsert + per-set artifact idioms round-trip.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class BackupDestinationRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM backup_artifact").fetch().rowsUpdated().block();
        db.sql("DELETE FROM backup_set").fetch().rowsUpdated().block();
        db.sql("DELETE FROM backup_destination").fetch().rowsUpdated().block();
    }

    private BackupDestinationRepository destRepo() {
        return new BackupDestinationRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.cloudbackup.BackupDestinationR2dbcRepository.class));
    }

    private BackupSetRepository setRepo() {
        return new BackupSetRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.cloudbackup.BackupSetR2dbcRepository.class));
    }

    private BackupArtifactRepository artRepo() {
        return new BackupArtifactRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.cloudbackup.BackupArtifactR2dbcRepository.class));
    }

    // ── destination upsert (insert-then-update; UNIQUE per domain) ───────────────────────

    @Test
    void upsert_insertsThenUpdatesInPlace() {
        BackupDestinationRepository r = destRepo();
        BackupDestination d1 = r.upsert(BackupDestinationKind.OBJECT_STORE, "s3://b1",
                "secret-ref-1", "brandx", "alice").block();
        assertThat(d1.kind()).isEqualTo(BackupDestinationKind.OBJECT_STORE);
        assertThat(d1.destinationRef()).isEqualTo("s3://b1");
        // a second upsert for the SAME domain UPDATEs in place (UNIQUE on domain) — no dup.
        BackupDestination d2 = r.upsert(BackupDestinationKind.NODE_STORAGE, "pool-7",
                null, "brandx", "bob").block();
        assertThat(d2.id()).isEqualTo(d1.id());                 // same row
        assertThat(d2.kind()).isEqualTo(BackupDestinationKind.NODE_STORAGE);
        assertThat(d2.destinationRef()).isEqualTo("pool-7");
        assertThat(d2.secretRef()).isNull();
        assertThat(r.findByDomain("brandx").block().updatedBy()).isEqualTo("bob");
    }

    @Test
    void perDomain_independent() {
        BackupDestinationRepository r = destRepo();
        r.upsert(BackupDestinationKind.OBJECT_STORE, "s3://x", "sx", "brandx", "alice").block();
        r.upsert(BackupDestinationKind.NODE_STORAGE, "pool-y", null, "brandy", "bob").block();
        assertThat(r.findByDomain("brandx").block().destinationRef()).isEqualTo("s3://x");
        assertThat(r.findByDomain("brandy").block().destinationRef()).isEqualTo("pool-y");
    }

    // ── artifacts (FK -> set; per-set list; status) ──────────────────────────────────────

    @Test
    void artifacts_insertUnderSet_thenListAndStatus() {
        BackupSet set = setRepo().insert("k1", 1L, BackupCloudScope.DOMAIN, "brandx", "alice",
                List.of("postgres", "matrix"), BackupDestinationKind.OBJECT_STORE, "s3://b", null).block();
        BackupArtifactRepository a = artRepo();
        a.insert(set.id(), "postgres", BackupArtifact.KIND_DB_DUMP).block();
        BackupArtifact pv = a.insert(set.id(), "matrix", BackupArtifact.KIND_PV_SNAPSHOT).block();
        List<BackupArtifact> list = a.listForSet(set.id()).collectList().block();
        assertThat(list).hasSize(2);
        assertThat(list).extracting(BackupArtifact::service)
                .containsExactlyInAnyOrder("postgres", "matrix");
        // status transition stamps size + completed_at.
        assertThat(a.markStatus(pv.id(), BackupArtifact.STATUS_COMPLETE, 1024L).block()).isEqualTo(1L);
        BackupArtifact done = a.listForSet(set.id()).collectList().block().stream()
                .filter(x -> x.service().equals("matrix")).findFirst().orElseThrow();
        assertThat(done.status()).isEqualTo(BackupArtifact.STATUS_COMPLETE);
        assertThat(done.sizeBytes()).isEqualTo(1024L);
    }
}
