package systems.hugmesh.adminbff.device;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code device_registry} — the identity + physical ownership
 * + DOMAIN RESIDENCY of each mesh node (schema in Liquibase
 * {@code db/changelog/011-device-license-registry.xml}).
 *
 * <p>Backed by the Spring Data {@link DeviceRowRepository} (no raw {@code DatabaseClient});
 * maps the {@link DeviceRow} entity to the {@link Device} domain record. The ADMIN read
 * surface is per-domain; the signed export reads are UNSCOPED.
 */
@Repository
public class DeviceRegistryRepository {

    private final DeviceRowRepository repo;

    public DeviceRegistryRepository(DeviceRowRepository repo) {
        this.repo = repo;
    }

    /** Register a new device (DB-generated id) and return it. The INSERT omits {@code id}
     *  (filled from the {@code (gen_random_uuid())::text} column DEFAULT, changelog 200) and
     *  {@code RETURNING id} hands back the generated string, which we read back by that id to
     *  return the persisted row (same field order/values as before). */
    public Mono<Device> insert(Device d) {
        return repo.insertReturningId(d.machineKeyFp(), d.hostname(), d.tailnetId(),
                        d.imageType(), d.hardwareClass(), d.ownerType(), d.physicalOwner(),
                        d.domain(), d.meshId(), Instant.now(), d.lastSeenAt())
                .flatMap(genId -> repo.findById(genId).map(DeviceRow::toDomain));
    }

    /** The device with this stable machine-key fingerprint, if any. UNSCOPED. */
    public Mono<Device> findByMachineKey(String machineKeyFp) {
        return repo.findByMachineKeyFp(machineKeyFp).map(DeviceRow::toDomain);
    }

    /** The device with this id, if any. UNSCOPED — used by the grant flow + export. */
    public Mono<Device> findById(String id) {
        return repo.findById(id).map(DeviceRow::toDomain);
    }

    /** ALL devices (every brand). UNSCOPED — used by the signed export only. */
    public Flux<Device> listAll() {
        return repo.findAllByOrderByDomainAscHostnameAsc().map(DeviceRow::toDomain);
    }

    /** All devices in a single mesh (every brand). UNSCOPED — the per-mesh export scan. */
    public Flux<Device> listByMesh(String meshId) {
        return repo.findByMeshIdOrderByDomainAscHostnameAsc(meshId).map(DeviceRow::toDomain);
    }

    /** Devices VISIBLE to the given tenant scope — the ADMIN read surface. */
    public Flux<Device> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByHostname(domain).map(DeviceRow::toDomain);
        }
        return listAll();
    }

    /**
     * De-register a device by id WITHIN the given tenant scope. A scoped principal's
     * delete only affects a row that is BOTH the id AND in their brand; SUPERADMIN deletes
     * any id. Returns the rows-deleted count.
     */
    public Mono<Long> delete(String id, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.deleteByIdAndDomain(id, domain);
        }
        return repo.existsById(id)
                .flatMap(exists -> exists ? repo.deleteById(id).thenReturn(1L) : Mono.just(0L));
    }
}
