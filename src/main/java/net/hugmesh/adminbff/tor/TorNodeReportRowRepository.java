package net.hugmesh.adminbff.tor;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code tor_node_report} (changeset 360). One row per reporting
 * fingerprint; a re-report REPLACES the exported onions (the node's files are the truth, so
 * a withdrawn domain onion disappears here too) and bumps the report counter.
 */
public interface TorNodeReportRowRepository extends ReactiveCrudRepository<TorNodeReportRow, String> {

    /**
     * Atomic INSERT-or-REPLACE on the UNIQUE fingerprint. The INSERT arm omits {@code id}
     * (DB-generated, changelog-200 idiom) and starts the counter at 1; the conflict arm
     * replaces both onion columns, stamps {@code last_reported_at} and increments the counter.
     */
    String UPSERT = """
            INSERT INTO tor_node_report (machine_key_fp, primary_onion, domain_onions) \
            VALUES (:fp, :primaryOnion, :domainOnions) \
            ON CONFLICT (machine_key_fp) DO UPDATE SET \
              primary_onion = EXCLUDED.primary_onion, \
              domain_onions = EXCLUDED.domain_onions, \
              last_reported_at = now(), \
              report_count = tor_node_report.report_count + 1""";

    @Modifying
    @Query(UPSERT)
    Mono<Long> upsert(@Param("fp") String fp,
                      @Param("primaryOnion") String primaryOnion,
                      @Param("domainOnions") String domainOnions);

    /** The report for this fingerprint, if any (UNIQUE on machine_key_fp). */
    Mono<TorNodeReportRow> findByMachineKeyFp(String machineKeyFp);

    /** Every report, by fingerprint. */
    Flux<TorNodeReportRow> findByOrderByMachineKeyFpAsc();
}
