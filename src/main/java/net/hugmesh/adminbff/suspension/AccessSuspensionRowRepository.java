package net.hugmesh.adminbff.suspension;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code access_suspension} (changeset 008 + 010).
 * Most reads are derived finders; the {@code PROFILE-first} ordered scan ({@code ORDER BY
 * CASE ...}) and the two state-guarded / partial UPDATEs are {@code @Query} static-final
 * constants (an {@code ORDER BY CASE} + {@code NULLS FIRST} and a CAS-on-state UPDATE are
 * not derivable). The {@link AccessSuspensionRepository} facade maps rows to/from the
 * {@link AccessSuspension} domain record.
 */
public interface AccessSuspensionRowRepository
        extends ReactiveCrudRepository<AccessSuspensionRow, String> {

    /**
     * Insert a new suspension with a DB-generated id. The {@code id} is OMITTED so Postgres
     * fills it from the {@code (gen_random_uuid())::text} column DEFAULT (changelog 200);
     * {@code RETURNING id} reads the generated varchar(36) string back. A plain (non-{@code
     * @Modifying}) {@code @Query} returning the new id — the deterministic, mod-bff-proven
     * path. The 11 supplied columns match the {@link AccessSuspensionRow} column order
     * (id excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO access_suspension \
            (casdoor_user, localpart, role, state, suspended_at, expires_at, restore_role, \
             propagation_state, reason, set_by, domain) \
            VALUES (:casdoor_user, :localpart, :role, :state, :suspended_at, :expires_at, \
             :restore_role, :propagation_state, :reason, :set_by, :domain) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("casdoor_user") String casdoorUser,
                                   @Param("localpart") String localpart,
                                   @Param("role") String role,
                                   @Param("state") String state,
                                   @Param("suspended_at") Instant suspendedAt,
                                   @Param("expires_at") Instant expiresAt,
                                   @Param("restore_role") boolean restoreRole,
                                   @Param("propagation_state") String propagationState,
                                   @Param("reason") String reason,
                                   @Param("set_by") String setBy,
                                   @Param("domain") String domain);

    /** Active suspension for a (user, role) — UNSCOPED. */
    Mono<AccessSuspensionRow> findByCasdoorUserAndRoleAndState(String casdoorUser, String role, String state);

    /** Active suspension for a (user, role) within a brand — the scoped admin surface. */
    Mono<AccessSuspensionRow> findByCasdoorUserAndRoleAndStateAndDomain(
            String casdoorUser, String role, String state, String domain);

    /** All ACTIVE suspensions for a role, user-ordered (the loop's MINUS set). */
    Flux<AccessSuspensionRow> findByRoleAndStateOrderByCasdoorUser(String role, String state);

    /** Any ACTIVE suspension on a localpart for a platform role (the broker guard). */
    Flux<AccessSuspensionRow> findByLocalpartAndRoleAndState(String localpart, String role, String state);

    /** All ACTIVE suspensions (every brand), role-then-user ordered — the reconcile set. */
    Flux<AccessSuspensionRow> findByStateOrderByRoleAscCasdoorUserAsc(String state);

    /** All ACTIVE suspensions for a brand, role-then-user ordered — the scoped admin read. */
    Flux<AccessSuspensionRow> findByStateAndDomainOrderByRoleAscCasdoorUserAsc(String state, String domain);

    /**
     * Every ACTIVE suspension on a localpart (any role, any brand), widest-impact first
     * (PROFILE ahead of platform roles), then by expiry NULLS FIRST. {@code ORDER BY CASE}
     * + {@code NULLS FIRST} is not derivable, so it is a {@code @Query} constant.
     */
    String ACTIVE_BY_LOCALPART =
            "SELECT id, casdoor_user, localpart, role, state, suspended_at, expires_at, "
            + "restore_role, propagation_state, reason, set_by, domain "
            + "FROM access_suspension WHERE localpart = :localpart AND state = 'active' "
            + "ORDER BY CASE WHEN role = 'PROFILE' THEN 0 ELSE 1 END, expires_at NULLS FIRST";

    @Query(ACTIVE_BY_LOCALPART)
    Flux<AccessSuspensionRow> activeByLocalpart(String localpart);

    /** The expiry working set: timed ACTIVE+restorable rows whose TTL has passed. */
    Flux<AccessSuspensionRow>
        findByStateAndRestoreRoleTrueAndExpiresAtIsNotNullAndExpiresAtLessThanEqualOrderByExpiresAt(
            String state, Instant now);

    /** CAS {@code active -> restored} for one id; returns rows updated (1=won, 0=lost). */
    String MARK_RESTORED =
            "UPDATE access_suspension SET state = 'restored' WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(MARK_RESTORED)
    Mono<Long> markRestored(String id);

    /** Record the homeserver-leg outcome (pending/applied/failed) for a row. */
    String UPDATE_PROP =
            "UPDATE access_suspension SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);
}
