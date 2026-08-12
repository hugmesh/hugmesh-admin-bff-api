package net.hugmesh.adminbff.sshissue;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code admin_ssh_issued_key} — the issuance AUDIT record for
 * admin SSH key-ISSUANCE (schema in Liquibase {@code db/changelog/172-admin-ssh-issued-key.xml}).
 *
 * <p>Backed by the Spring Data {@link AdminSshIssuedKeyRowRepository} (no raw
 * {@code DatabaseClient}); maps the {@link AdminSshIssuedKeyRow} entity to the {@link
 * AdminSshIssuedKey} domain record. NO private-key column exists. {@code insert} persists
 * the NON-SECRET public line + fingerprint; {@code markDownloaded} stamps the single-use
 * download; {@code revoke} is a CAS {@code issued -> revoked} that NEVER deletes.
 */
@Repository
public class AdminSshIssuedKeyRepository {

    private final AdminSshIssuedKeyRowRepository repo;

    public AdminSshIssuedKeyRepository(AdminSshIssuedKeyRowRepository repo) {
        this.repo = repo;
    }

    /** Insert a new {@code issued} audit row with a DB-generated id (changelog 200). */
    public Mono<AdminSshIssuedKey> insert(AdminSshIssuedKey k) {
        Instant issuedAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200) and the not-yet-set downloaded_at/revoked_at/revoked_by (default NULL); RETURNING id
        // hands back the generated string, mapped into the persisted record with the SAME field
        // order/values as before (state ISSUED, NO private-key column).
        return repo.insertReturningId(k.deviceId(), k.licenseId(), k.operator(), k.keyType(),
                        k.publicKey(), k.fingerprint(), k.issuedBy(), issuedAt,
                        AdminSshIssuedKey.STATE_ISSUED, k.domain())
                .map(genId -> new AdminSshIssuedKey(genId, k.deviceId(), k.licenseId(), k.operator(),
                        k.keyType(), k.publicKey(), k.fingerprint(), k.issuedBy(), issuedAt,
                        null, AdminSshIssuedKey.STATE_ISSUED, k.domain(), null, null));
    }

    /** A single row by id (UNSCOPED). */
    public Mono<AdminSshIssuedKey> findById(String id) {
        return repo.findById(id).map(AdminSshIssuedKeyRow::toDomain);
    }

    /** Active ({@code issued}) credentials targeting one device id, VISIBLE to the given scope. */
    public Flux<AdminSshIssuedKey> findActiveForDevice(String deviceId, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDeviceIdAndStateAndDomainOrderByOperatorAscIssuedAtDesc(
                            deviceId, AdminSshIssuedKey.STATE_ISSUED, domain)
                    .map(AdminSshIssuedKeyRow::toDomain);
        }
        return repo.findByDeviceIdAndStateOrderByOperatorAscIssuedAtDesc(
                        deviceId, AdminSshIssuedKey.STATE_ISSUED)
                .map(AdminSshIssuedKeyRow::toDomain);
    }

    /** ALL active credentials for (operator, deviceId), UNSCOPED — the rotation-replaces predicate. */
    public Flux<AdminSshIssuedKey> findActiveForOperatorDevice(String operator, String deviceId) {
        return repo.findByOperatorAndDeviceIdAndStateOrderByIssuedAtDesc(
                        operator, deviceId, AdminSshIssuedKey.STATE_ISSUED)
                .map(AdminSshIssuedKeyRow::toDomain);
    }

    /** Stamp {@code downloaded_at = now()} for one row, single-use guarded (1 = won, 0 = lost). */
    public Mono<Long> markDownloaded(String id) {
        return repo.markDownloaded(id);
    }

    /** CAS {@code issued -> revoked} for one row id (1 = won, 0 = already revoked / out of scope). */
    public Mono<Long> revoke(String id, String revokedBy, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.revokeScoped(id, revokedBy, domain);
        }
        return repo.revokeUnscoped(id, revokedBy);
    }
}
