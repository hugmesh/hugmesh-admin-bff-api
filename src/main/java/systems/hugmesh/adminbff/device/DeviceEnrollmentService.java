package systems.hugmesh.adminbff.device;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Records node LIVENESS self-reports into {@code device_enrollment} (UPSERT by machine_key_fp).
 * A thin pass-through to {@link DeviceEnrollmentRepository} — there is intentionally NO
 * authorization logic here, because the self-report channel confers NO access (the trust gate
 * is headscale + the SUPERADMIN assignment; this is reconciliation telemetry only).
 */
@Service
public class DeviceEnrollmentService {

    private final DeviceEnrollmentRepository repo;

    public DeviceEnrollmentService(DeviceEnrollmentRepository repo) {
        this.repo = repo;
    }

    /** UPSERT a self-report; returns the resulting liveness row (with the bumped count). */
    public Mono<DeviceEnrollment> record(String machineKeyFp, String hostname, String meshId, String tailnetId) {
        return repo.upsert(machineKeyFp, hostname, meshId, tailnetId);
    }
}
