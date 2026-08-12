package net.hugmesh.adminbff.device;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code device_enrollment} (changeset 130). The
 * fingerprint lookup is a derived finder; the self-report bump is an {@code @Modifying
 * @Query} static-final constant (the atomic {@code report_count = report_count + 1}
 * increment is not expressible as a full-entity save). The {@link
 * DeviceEnrollmentRepository} facade composes these + {@code save} for the first-report
 * INSERT into the portable findByFp-then-update|insert upsert.
 */
public interface DeviceEnrollmentRowRepository extends ReactiveCrudRepository<DeviceEnrollmentRow, String> {

    /**
     * Insert a first-report row with a DB-generated id (changelog 200) — the upsert's INSERT
     * branch: {@code id} is OMITTED → filled from the {@code (gen_random_uuid())::text} column
     * DEFAULT; {@code RETURNING id} reads the generated varchar(36) back ({@code Mono<String>}).
     * Columns match the {@link DeviceEnrollmentRow} order (id excluded). The re-report bump
     * ({@link #bump}) is unchanged.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO device_enrollment \
            (machine_key_fp, hostname, mesh_id, tailnet_id, first_reported_at, last_reported_at, \
             report_count) \
            VALUES (:machineKeyFp, :hostname, :meshId, :tailnetId, :firstReportedAt, \
             :lastReportedAt, :reportCount) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("machineKeyFp") String machineKeyFp,
                                   @Param("hostname") String hostname,
                                   @Param("meshId") String meshId,
                                   @Param("tailnetId") String tailnetId,
                                   @Param("firstReportedAt") Instant firstReportedAt,
                                   @Param("lastReportedAt") Instant lastReportedAt,
                                   @Param("reportCount") long reportCount);

    /** The enrollment row for this fingerprint, if any (UNIQUE on machine_key_fp). */
    Mono<DeviceEnrollmentRow> findByMachineKeyFp(String machineKeyFp);

    /** Atomic re-report bump: last_reported_at=now(), report_count+1, refresh hints. */
    String BUMP =
            "UPDATE device_enrollment SET last_reported_at = now(), "
            + "report_count = report_count + 1, hostname = :host, mesh_id = :mesh, "
            + "tailnet_id = :tn WHERE machine_key_fp = :fp";

    @Modifying
    @Query(BUMP)
    Mono<Long> bump(String fp, String host, String mesh, String tn);
}
