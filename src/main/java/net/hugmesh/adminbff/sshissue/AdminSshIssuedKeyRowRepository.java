package net.hugmesh.adminbff.sshissue;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code admin_ssh_issued_key} (changeset 172).
 * Derived finders cover the scoped/unscoped per-device + per-operator-device reads; the
 * single-use download stamp and the CAS-on-state audited revoke (scoped + unscoped) are
 * {@code @Query} static-final constants. The {@link AdminSshIssuedKeyRepository} facade
 * maps rows to/from {@link AdminSshIssuedKey}.
 */
public interface AdminSshIssuedKeyRowRepository extends ReactiveCrudRepository<AdminSshIssuedKeyRow, String> {

    /**
     * Insert a new {@code issued} audit row with a DB-generated id (changelog 200): {@code id} is
     * OMITTED → filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING
     * id} reads the generated varchar(36) back ({@code Mono<String>}). The not-yet-set {@code
     * downloaded_at}/{@code revoked_at}/{@code revoked_by} are OMITTED (default NULL — the
     * freshly-issued shape). NO private-key column exists. Columns match the
     * {@link AdminSshIssuedKeyRow} order (id + those three excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO admin_ssh_issued_key \
            (device_id, license_id, operator, key_type, public_key, fingerprint, issued_by, \
             issued_at, state, domain) \
            VALUES (:deviceId, :licenseId, :operator, :keyType, :publicKey, :fingerprint, \
             :issuedBy, :issuedAt, :state, :domain) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("deviceId") String deviceId,
                                   @Param("licenseId") String licenseId,
                                   @Param("operator") String operator,
                                   @Param("keyType") String keyType,
                                   @Param("publicKey") String publicKey,
                                   @Param("fingerprint") String fingerprint,
                                   @Param("issuedBy") String issuedBy,
                                   @Param("issuedAt") Instant issuedAt,
                                   @Param("state") String state,
                                   @Param("domain") String domain);

    Flux<AdminSshIssuedKeyRow> findByDeviceIdAndStateAndDomainOrderByOperatorAscIssuedAtDesc(
            String deviceId, String state, String domain);

    Flux<AdminSshIssuedKeyRow> findByDeviceIdAndStateOrderByOperatorAscIssuedAtDesc(
            String deviceId, String state);

    Flux<AdminSshIssuedKeyRow> findByOperatorAndDeviceIdAndStateOrderByIssuedAtDesc(
            String operator, String deviceId, String state);

    /** Single-use download stamp (guarded on un-downloaded + issued). */
    String MARK_DOWNLOADED =
            "UPDATE admin_ssh_issued_key SET downloaded_at = now() "
            + "WHERE id = :id AND downloaded_at IS NULL AND state = 'issued'";

    @Modifying
    @Query(MARK_DOWNLOADED)
    Mono<Long> markDownloaded(String id);

    String REVOKE_SCOPED =
            "UPDATE admin_ssh_issued_key SET state = 'revoked', revoked_at = now(), revoked_by = :by "
            + "WHERE id = :id AND state = 'issued' AND domain = :domain";

    @Modifying
    @Query(REVOKE_SCOPED)
    Mono<Long> revokeScoped(String id, String by, String domain);

    String REVOKE_UNSCOPED =
            "UPDATE admin_ssh_issued_key SET state = 'revoked', revoked_at = now(), revoked_by = :by "
            + "WHERE id = :id AND state = 'issued'";

    @Modifying
    @Query(REVOKE_UNSCOPED)
    Mono<Long> revokeUnscoped(String id, String by);
}
