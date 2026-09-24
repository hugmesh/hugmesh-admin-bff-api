package net.hugmesh.adminbff.tor;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Changeset 360 over the real Postgres test store: both tables apply, and each ON CONFLICT
 * upsert keeps ONE row per fingerprint (hugmesh-admin-bff-api#108):
 * <ul>
 *   <li>a re-report REPLACES the onions (a withdrawn domain disappears) and bumps the count;</li>
 *   <li>an upstream write sets managed, stores NULL for the agent default, and bumps the
 *       per-node config generation on every write.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class TorNodeRepositoryTest {

    @Autowired DatabaseClient db;

    static final String A = "a".repeat(56) + ".onion";
    static final String B = "b".repeat(56) + ".onion";
    static final String C = "c".repeat(56) + ".onion";

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM tor_node_report").fetch().rowsUpdated().block();
        db.sql("DELETE FROM tor_node_config").fetch().rowsUpdated().block();
    }

    private TorNodeReportRowRepository reports() {
        return R2dbcRepos.of(db, TorNodeReportRowRepository.class);
    }

    private TorNodeConfigRowRepository configs() {
        return R2dbcRepos.of(db, TorNodeConfigRowRepository.class);
    }

    private long count(String table, String fp) {
        return db.sql("SELECT COUNT(*) AS c FROM " + table + " WHERE machine_key_fp = :fp").bind("fp", fp)
                .map((r, m) -> r.get("c", Long.class)).first().block();
    }

    @Test
    void report_firstInsert_thenReplace_oneRow_countBumps_withdrawnDomainGone() {
        TorNodeReportRowRepository repo = reports();
        repo.upsert("fp-1", A, TorNodeReport.encodeDomainOnions(Map.of("brandb", B, "zeta", C))).block();
        TorNodeReport first = repo.findByMachineKeyFp("fp-1").block().toDomain();
        assertThat(first.reportCount()).isEqualTo(1L);
        assertThat(first.domainOnions()).containsOnlyKeys("brandb", "zeta");

        repo.upsert("fp-1", A, TorNodeReport.encodeDomainOnions(Map.of("brandb", B))).block();
        TorNodeReportRow again = repo.findByMachineKeyFp("fp-1").block();
        assertThat(again.id()).isNotBlank();                 // DB-generated id
        assertThat(again.reportCount()).isEqualTo(2L);
        assertThat(again.toDomain().domainOnions()).containsExactly(Map.entry("brandb", B));
        assertThat(count("tor_node_report", "fp-1")).isEqualTo(1L);
    }

    @Test
    void report_beforeMint_nullPrimary_emptyDomains() {
        reports().upsert("fp-2", null, "").block();
        TorNodeReport r = reports().findByMachineKeyFp("fp-2").block().toDomain();
        assertThat(r.primaryOnion()).isNull();
        assertThat(r.domainOnions()).isEmpty();
    }

    /**
     * The PRIMARY half of "a re-report replaces the previous one": a node that reported
     * before tor minted its onion (primary null, the normal boot order) must pick the onion up
     * on its next report, and a re-minted primary (HS state lost, key rotated) must replace the
     * old one. The domain-half test above sends the same primary twice, so it cannot see this.
     */
    @Test
    void report_rereport_replacesThePrimary_nullToOnion_thenOnionToOnion() {
        TorNodeReportRowRepository repo = reports();
        repo.upsert("fp-3", null, "").block();
        assertThat(repo.findByMachineKeyFp("fp-3").block().toDomain().primaryOnion()).isNull();

        repo.upsert("fp-3", A, "").block();
        TorNodeReport minted = repo.findByMachineKeyFp("fp-3").block().toDomain();
        assertThat(minted.primaryOnion()).isEqualTo(A);
        assertThat(minted.reportCount()).isEqualTo(2L);

        repo.upsert("fp-3", B, "").block();
        TorNodeReport reminted = repo.findByMachineKeyFp("fp-3").block().toDomain();
        assertThat(reminted.primaryOnion()).isEqualTo(B);
        assertThat(reminted.reportCount()).isEqualTo(3L);
        assertThat(count("tor_node_report", "fp-3")).isEqualTo(1L);
    }

    @Test
    void upstream_insertThenUpdate_managed_generationBumps_nullIsStored() {
        TorNodeConfigRowRepository repo = configs();
        repo.upsertUpstream("fp-1", "10.0.0.7:443", "root").block();
        TorNodeConfig c1 = repo.findByMachineKeyFp("fp-1").block().toDomain();
        assertThat(c1.upstreamManaged()).isTrue();
        assertThat(c1.upstream()).isEqualTo("10.0.0.7:443");
        assertThat(c1.configGeneration()).isEqualTo(1L);

        repo.upsertUpstream("fp-1", null, "root2").block();
        TorNodeConfig c2 = repo.findByMachineKeyFp("fp-1").block().toDomain();
        assertThat(c2.upstreamManaged()).isTrue();
        assertThat(c2.upstream()).isNull();
        assertThat(c2.configGeneration()).isEqualTo(2L);
        assertThat(c2.updatedBy()).isEqualTo("root2");
        assertThat(count("tor_node_config", "fp-1")).isEqualTo(1L);

        repo.upsertUpstream("fp-9", "[fd00::1]:443", "root").block();
        assertThat(repo.findByOrderByMachineKeyFpAsc().map(TorNodeConfigRow::machineKeyFp).collectList().block())
                .containsExactly("fp-1", "fp-9");
    }
}
