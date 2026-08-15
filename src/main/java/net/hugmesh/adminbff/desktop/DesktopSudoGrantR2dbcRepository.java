package net.hugmesh.adminbff.desktop;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Collection;

/**
 * Reactive (R2DBC) Spring Data store for {@code desktop_sudo_grant} (changeset 140). The active
 * lookup, scoped/unscoped admin lists, per-device active scan, and full active set are derived
 * finders; the {@code MAX(generation)} aggregate, the two state-guarded CAS revoke UPDATEs
 * (scoped + unscoped), and the propagation-state partial UPDATE are {@code @Query} static-final
 * constants (an aggregate and CAS-on-state UPDATEs are not derivable). The
 * {@link DesktopSudoGrantRepository} facade maps rows to/from the {@link DesktopSudoGrant} domain
 * record.
 */
public interface DesktopSudoGrantR2dbcRepository
        extends ReactiveCrudRepository<DesktopSudoGrantRow, String> {

    /**
     * Insert a new ACTIVE grant with a DB-generated id (changelog 200): {@code id} is OMITTED →
     * filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads
     * the generated varchar(36) back ({@code Mono<String>}). The not-yet-set {@code revoked_at}/
     * {@code revoked_by} are OMITTED (default NULL — the fresh-grant shape). Columns match the
     * {@link DesktopSudoGrantRow} order (id + revoked_at + revoked_by excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO desktop_sudo_grant \
            (subject, device_id, state, granted_by, granted_at, domain, propagation_state, \
             generation) \
            VALUES (:subject, :deviceId, :state, :grantedBy, :grantedAt, :domain, \
             :propagationState, :generation) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("subject") String subject,
                                   @Param("deviceId") String deviceId,
                                   @Param("state") String state,
                                   @Param("grantedBy") String grantedBy,
                                   @Param("grantedAt") Instant grantedAt,
                                   @Param("domain") String domain,
                                   @Param("propagationState") String propagationState,
                                   @Param("generation") long generation);

    /** The active grant for (subject, deviceId), if any — the idempotency / entitlement check. */
    Mono<DesktopSudoGrantRow> findBySubjectAndDeviceIdAndState(
            String subject, String deviceId, String state);

    /** Grants for a brand, subject then newest first — the scoped admin read. */
    Flux<DesktopSudoGrantRow> findByDomainOrderBySubjectAscGrantedAtDesc(String domain);

    /** ALL grants (unscoped SUPERADMIN), domain then subject then newest first. */
    Flux<DesktopSudoGrantRow> findByOrderByDomainAscSubjectAscGrantedAtDesc();

    /** All active grants on one device, by subject — the per-device entitlement view. */
    Flux<DesktopSudoGrantRow> findByDeviceIdAndStateOrderBySubject(String deviceId, String state);

    /** ALL active grants (every brand), by subject — the full entitlement working set. */
    Flux<DesktopSudoGrantRow> findByStateOrderBySubject(String state);

    /** A subject's grants in one state (any device) — the Casdoor role-membership floor
     *  (member iff >=1 active grant remains). */
    Flux<DesktopSudoGrantRow> findBySubjectAndState(String subject, String state);

    /** Rows still owing IdP propagation (pending / failed) — the claim worker's sweep set,
     *  oldest mutate first. */
    Flux<DesktopSudoGrantRow> findByPropagationStateInOrderByGenerationAsc(
            Collection<String> propagationStates);

    /** The current MAX(generation) across ALL grant rows; 0 when empty. */
    String MAX_GENERATION = "SELECT COALESCE(MAX(generation), 0) FROM desktop_sudo_grant";

    @Query(MAX_GENERATION)
    Mono<Long> maxGeneration();

    /** CAS {@code active -> revoked} for one id in a brand, stamping audit + bumping gen. */
    String REVOKE_SCOPED =
            "UPDATE desktop_sudo_grant "
            + "SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "    generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active' AND domain = :domain";

    @Modifying
    @Query(REVOKE_SCOPED)
    Mono<Long> revokeScoped(String id, String by, long gen, String domain);

    /** CAS {@code active -> revoked} for one id (unscoped SUPERADMIN). */
    String REVOKE_ALL =
            "UPDATE desktop_sudo_grant "
            + "SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "    generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(REVOKE_ALL)
    Mono<Long> revokeAll(String id, String by, long gen);

    /** Record the push-with-ack propagation outcome for a row. */
    String UPDATE_PROP = "UPDATE desktop_sudo_grant SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);
}
