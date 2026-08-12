package net.hugmesh.adminbff.device;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code device_enrollment} — the liveness-reconciliation
 * self-report channel (schema in Liquibase {@code db/changelog/130-device-enrollment.xml}).
 *
 * <p>Backed by the Spring Data {@link DeviceEnrollmentRowRepository} (no raw
 * {@code DatabaseClient}); maps the {@link DeviceEnrollmentRow} entity to the
 * {@link DeviceEnrollment} domain record. The upsert is the portable
 * findByFp-then-update|insert idiom; the re-report bump is the atomic increment UPDATE.
 *
 * <p>NO authorizing columns are read or written here — this is reconciliation telemetry only.
 */
@Repository
public class DeviceEnrollmentRepository {

    private final DeviceEnrollmentRowRepository repo;

    public DeviceEnrollmentRepository(DeviceEnrollmentRowRepository repo) {
        this.repo = repo;
    }

    /** The enrollment row for this fingerprint, if any. UNIQUE on machine_key_fp. */
    public Mono<DeviceEnrollment> findByMachineKey(String machineKeyFp) {
        return repo.findByMachineKeyFp(machineKeyFp).map(DeviceEnrollmentRow::toDomain);
    }

    /**
     * UPSERT a self-report. A first report INSERTs (report_count=1); a re-report bumps
     * last_reported_at + report_count and refreshes the reconciliation hints. Returns the
     * resulting row.
     */
    public Mono<DeviceEnrollment> upsert(String machineKeyFp, String hostname, String meshId, String tailnetId) {
        return repo.findByMachineKeyFp(machineKeyFp)
                .flatMap(existing -> repo.bump(machineKeyFp, hostname, meshId, tailnetId)
                        .then(findByMachineKey(machineKeyFp)))
                .switchIfEmpty(Mono.defer(() -> insert(machineKeyFp, hostname, meshId, tailnetId)));
    }

    private Mono<DeviceEnrollment> insert(String fp, String hostname, String meshId, String tailnetId) {
        Instant now = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id hands back the generated string, mapped into the persisted
        // DeviceEnrollment with the SAME field order/values as before (report_count=1, both
        // timestamps = now).
        return repo.insertReturningId(fp, hostname, meshId, tailnetId, now, now, 1L)
                .map(genId -> new DeviceEnrollment(genId, fp, hostname, meshId, tailnetId,
                        now, now, 1L));
    }
}
