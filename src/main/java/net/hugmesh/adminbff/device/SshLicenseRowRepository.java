package net.hugmesh.adminbff.device;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code device_ssh_license} (changeset 011).
 * Derived finders cover the idempotency lookups + the scoped/unscoped ordered lists; the
 * {@code MAX(generation)} aggregate and the CAS-on-state audited UPDATEs (revoke,
 * replaceFingerprints) + the partial propagation-state UPDATE are {@code @Query}
 * static-final constants (aggregates + CAS-on-state are not derivable). The {@link
 * SshLicenseRepository} facade maps rows to/from {@link SshLicense}.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 */
public interface SshLicenseRowRepository extends ReactiveCrudRepository<SshLicenseRow, String> {

    /**
     * Insert a new license with a DB-generated id (id OMITTED → filled from the column
     * DEFAULT; {@code RETURNING id} reads the generated varchar(36) back). The nullable
     * {@code revoked_at}/{@code revoked_by} are OMITTED (they default NULL — exactly the
     * fresh-license shape). The supplied columns match the {@link SshLicenseRow} column
     * order (id + the two revoke-audit columns excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO device_ssh_license \
            (operator, scope_type, device_id, target_domain, key_fingerprints, state, \
             granted_by, granted_at, domain, propagation_state, generation) \
            VALUES (:operator, :scope_type, :device_id, :target_domain, :key_fingerprints, \
             :state, :granted_by, :granted_at, :domain, :propagation_state, :generation) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("operator") String operator,
                                   @Param("scope_type") String scopeType,
                                   @Param("device_id") String deviceId,
                                   @Param("target_domain") String targetDomain,
                                   @Param("key_fingerprints") String keyFingerprints,
                                   @Param("state") String state,
                                   @Param("granted_by") String grantedBy,
                                   @Param("granted_at") Instant grantedAt,
                                   @Param("domain") String domain,
                                   @Param("propagation_state") String propagationState,
                                   @Param("generation") long generation);

    Mono<SshLicenseRow> findByOperatorAndDeviceIdAndState(String operator, String deviceId, String state);

    Mono<SshLicenseRow> findByOperatorAndTargetDomainAndState(String operator, String targetDomain, String state);

    /** Scoped admin list: a brand's rows, operator then granted_at DESC. */
    Flux<SshLicenseRow> findByDomainOrderByOperatorAscGrantedAtDesc(String domain);

    /** Unscoped admin list: all rows, domain then operator then granted_at DESC. */
    Flux<SshLicenseRow> findAllByOrderByDomainAscOperatorAscGrantedAtDesc();

    /** Scoped: active DEVICE licenses for a device in a brand, operator-ordered. */
    Flux<SshLicenseRow> findByDeviceIdAndStateAndDomainOrderByOperator(
            String deviceId, String state, String domain);

    /** Unscoped: active DEVICE licenses for a device, operator-ordered. */
    Flux<SshLicenseRow> findByDeviceIdAndStateOrderByOperator(String deviceId, String state);

    /** All active licenses (every brand), operator-ordered — the signed export working set. */
    Flux<SshLicenseRow> findByStateOrderByOperator(String state);

    /** The current MAX(generation) across ALL rows (0 when empty). */
    String MAX_GENERATION = "SELECT COALESCE(MAX(generation), 0) AS g FROM device_ssh_license";

    @Query(MAX_GENERATION)
    Mono<Long> maxGeneration();

    /** CAS {@code active -> revoked} at a new generation, scoped to a brand, audited. */
    String REVOKE_SCOPED =
            "UPDATE device_ssh_license "
            + "SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "    generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active' AND domain = :domain";

    @Modifying
    @Query(REVOKE_SCOPED)
    Mono<Long> revokeScoped(String id, String by, long gen, String domain);

    /** CAS {@code active -> revoked} at a new generation, UNSCOPED, audited. */
    String REVOKE_UNSCOPED =
            "UPDATE device_ssh_license "
            + "SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "    generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(REVOKE_UNSCOPED)
    Mono<Long> revokeUnscoped(String id, String by, long gen);

    /** Replace the pinned key_fingerprints set wholesale at a new generation (active-guarded). */
    String REPLACE_FINGERPRINTS =
            "UPDATE device_ssh_license "
            + "SET key_fingerprints = :fps, generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(REPLACE_FINGERPRINTS)
    Mono<Long> replaceFingerprints(String id, String fps, long gen);

    /** Record the push-with-ack propagation outcome for a row. */
    String UPDATE_PROP =
            "UPDATE device_ssh_license SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);
}
