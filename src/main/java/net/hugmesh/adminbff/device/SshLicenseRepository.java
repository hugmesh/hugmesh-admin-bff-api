package net.hugmesh.adminbff.device;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code device_ssh_license} — the explicit
 * (operator x device|domain) SSH grant rows (schema in Liquibase
 * {@code db/changelog/011-device-license-registry.xml}).
 *
 * <p>Backed by the Spring Data {@link SshLicenseRowRepository} (no raw
 * {@code DatabaseClient}); maps the {@link SshLicenseRow} entity to the {@link SshLicense}
 * domain record. Grants are findActive-before-insert idempotent; revoke is a CAS
 * {@code active -> revoked} that NEVER deletes (the row is the audit trail); every mutate
 * bumps the monotonic {@code generation}.
 */
@Repository
public class SshLicenseRepository {

    private final SshLicenseRowRepository repo;

    public SshLicenseRepository(SshLicenseRowRepository repo) {
        this.repo = repo;
    }

    // ── grant (findActive-then-insert idempotency) ──────────────────────────────

    /** The active DEVICE license for (operator, deviceId), if any. UNSCOPED. */
    public Mono<SshLicense> findActiveDevice(String operator, String deviceId) {
        return repo.findByOperatorAndDeviceIdAndState(operator, deviceId, SshLicense.STATE_ACTIVE)
                .map(SshLicenseRow::toDomain);
    }

    /** The active DOMAIN license for (operator, targetDomain), if any. UNSCOPED. */
    public Mono<SshLicense> findActiveDomain(String operator, String targetDomain) {
        return repo.findByOperatorAndTargetDomainAndState(operator, targetDomain, SshLicense.STATE_ACTIVE)
                .map(SshLicenseRow::toDomain);
    }

    /** Insert a new ACTIVE license (DB-generated id) at the next monotonic generation. The
     *  INSERT omits {@code id} (filled from the {@code (gen_random_uuid())::text} column
     *  DEFAULT, changelog 200) and {@code RETURNING id} hands back the generated string, which
     *  we read back by that id to return the persisted row (same field order/values as
     *  before; the freshly-inserted row's revoke-audit columns are NULL). */
    public Mono<SshLicense> insertActive(SshLicense l, long generation) {
        return repo.insertReturningId(l.operator(), l.scopeType(), l.deviceId(), l.targetDomain(),
                        l.keyFingerprints(), SshLicense.STATE_ACTIVE, l.grantedBy(), Instant.now(),
                        l.domain(), SshLicense.PROP_PENDING, generation)
                .flatMap(genId -> repo.findById(genId).map(SshLicenseRow::toDomain));
    }

    // ── read (admin surface, scoped) ────────────────────────────────────────────

    /** ALL licenses VISIBLE to the given tenant scope — the ADMIN read surface. */
    public Flux<SshLicense> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByOperatorAscGrantedAtDesc(domain).map(SshLicenseRow::toDomain);
        }
        return repo.findAllByOrderByDomainAscOperatorAscGrantedAtDesc().map(SshLicenseRow::toDomain);
    }

    /** Active DEVICE licenses targeting one device id, VISIBLE to the given scope. */
    public Flux<SshLicense> activeForDevice(String deviceId, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDeviceIdAndStateAndDomainOrderByOperator(
                            deviceId, SshLicense.STATE_ACTIVE, domain)
                    .map(SshLicenseRow::toDomain);
        }
        return repo.findByDeviceIdAndStateOrderByOperator(deviceId, SshLicense.STATE_ACTIVE)
                .map(SshLicenseRow::toDomain);
    }

    // ── read (export, UNSCOPED) ─────────────────────────────────────────────────

    /** ALL active licenses (every brand). UNSCOPED — the signed export's full working set. */
    public Flux<SshLicense> listActiveAll() {
        return repo.findByStateOrderByOperator(SshLicense.STATE_ACTIVE).map(SshLicenseRow::toDomain);
    }

    /** A single license row by id (for fetching state after a CAS). UNSCOPED. */
    public Mono<SshLicense> findById(String id) {
        return repo.findById(id).map(SshLicenseRow::toDomain);
    }

    /** The current maximum {@code generation} across ALL rows (0 when empty). */
    public Mono<Long> maxGeneration() {
        return repo.maxGeneration().defaultIfEmpty(0L);
    }

    // ── revoke (CAS, audited, generation bump) ──────────────────────────────────

    /** CAS {@code active -> revoked} for one row id at a NEW generation (1 = won, 0 = lost). */
    public Mono<Long> revoke(String id, String revokedBy, long newGeneration, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.revokeScoped(id, revokedBy, newGeneration, domain);
        }
        return repo.revokeUnscoped(id, revokedBy, newGeneration);
    }

    /** Replace a row's pinned {@code key_fingerprints} wholesale at a NEW generation (active-guarded). */
    public Mono<Long> replaceFingerprints(String licenseId, String newFingerprints, long generation) {
        return repo.replaceFingerprints(licenseId, newFingerprints, generation);
    }

    /** Record the push-with-ack propagation outcome for a row. UNSCOPED. */
    public Mono<Long> updatePropagationState(String id, String propagationState) {
        return repo.updatePropagationState(id, propagationState);
    }
}
