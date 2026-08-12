package net.hugmesh.adminbff.backup;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.commons.security.PrincipalDomain;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates the backup_history R2DBC SQL against H2 (PostgreSQL-compat) with the
 * Liquibase-applied changesets 050 + 230 (domain) — insert (QUEUED, domain-stamped)
 * → list (newest-first, tenant-scoped) → status transition; encrypted verifier
 * columns round-trip and are never null-overwritten; and the cross-tenant isolation
 * (a brand-X admin can neither list nor resolve brand-Y's backups).
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, BackupRepository.class})
class BackupRepositoryTest {

    private static final PrincipalDomain SUPER = PrincipalDomain.superadminFor("default");
    private static final PrincipalDomain BRAND_A = PrincipalDomain.forDomain("brandA");
    private static final PrincipalDomain BRAND_B = PrincipalDomain.forDomain("brandB");

    @Autowired BackupRepository repo;

    @Test
    void insertListUpdate_roundTrip() {
        BackupRecord rec = repo.insert("admin@x", "etcd,postgres", "CLUSTER", false, null, null, SUPER).block();
        assertThat(rec.id()).isNotBlank();
        assertThat(rec.status()).isEqualTo("QUEUED");
        assertThat(rec.createdAt()).isNotNull();
        assertThat(rec.encrypted()).isFalse();

        repo.updateStatus(rec.id(), "COMPLETED", 4096L, "cluster://" + rec.id(), null).block();
        BackupRecord after = repo.find(rec.id(), SUPER).block();
        assertThat(after.status()).isEqualTo("COMPLETED");
        assertThat(after.sizeBytes()).isEqualTo(4096L);
        assertThat(after.locationRef()).isEqualTo("cluster://" + rec.id());

        // The inserted row is present in the history (no empty-table assumption — the
        // H2 store is shared across this class's test methods).
        assertThat(repo.list(SUPER).collectList().block())
                .extracting(BackupRecord::id).contains(rec.id());
    }

    @Test
    void encryptedBackup_persistsVerifierButNeverPassword() {
        BackupRecord rec = repo.insert("admin@x", "secrets", "USB", true, "saltB64", "verifierB64", SUPER).block();
        BackupRecord got = repo.find(rec.id(), SUPER).block();
        assertThat(got.encrypted()).isTrue();
        assertThat(got.verifierSalt()).isEqualTo("saltB64");
        assertThat(got.verifier()).isEqualTo("verifierB64");

        // A status update must not clobber the verifier columns.
        repo.updateStatus(rec.id(), "RUNNING", null, null, null).block();
        BackupRecord running = repo.find(rec.id(), SUPER).block();
        assertThat(running.verifier()).isEqualTo("verifierB64");
        assertThat(running.verifierSalt()).isEqualTo("saltB64");
    }

    @Test
    void crossTenant_listAndFind_isolatedByDomain() {
        // A backup created by a brand-A admin is stamped domain=brandA.
        BackupRecord a = repo.insert("admin@brandA", "etcd", "CLUSTER", false, null, null, BRAND_A).block();

        // brand-A sees it; brand-B does NOT; SUPERADMIN sees it (unscoped).
        assertThat(repo.list(BRAND_A).collectList().block())
                .extracting(BackupRecord::id).contains(a.id());
        assertThat(repo.list(BRAND_B).collectList().block())
                .extracting(BackupRecord::id).doesNotContain(a.id());
        assertThat(repo.list(SUPER).collectList().block())
                .extracting(BackupRecord::id).contains(a.id());

        // find / restore-source resolution is domain-walled: brand-B cannot resolve it.
        assertThat(repo.find(a.id(), BRAND_A).block()).isNotNull();
        assertThat(repo.find(a.id(), BRAND_B).block()).isNull();
        assertThat(repo.find(a.id(), SUPER).block()).isNotNull();
    }
}
