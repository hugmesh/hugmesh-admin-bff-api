package net.hugmesh.adminbff.egressvpn;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code vpn_node_assignment} (changeset 080).
 * Derived finders cover the scoped/unscoped lists + the per-node active read; the
 * COALESCE-keyed idempotency lookups, MAX(generation), the CAS-on-state audited revoke
 * (scoped/unscoped/by-config), and the partial propagation-state UPDATE are {@code @Query}
 * static-final constants. The {@link VpnNodeAssignmentRepository} facade maps rows to/from
 * {@link VpnNodeAssignment}.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 */
public interface VpnNodeAssignmentRowRepository extends ReactiveCrudRepository<VpnNodeAssignmentRow, String> {

    /**
     * Insert a new assignment with a DB-generated id (id OMITTED → filled from the column
     * DEFAULT; {@code RETURNING id} reads the generated varchar(36) back). The nullable
     * {@code revoked_at}/{@code revoked_by} are OMITTED (default NULL — the fresh-assignment
     * shape). The supplied columns match the {@link VpnNodeAssignmentRow} column order
     * (id + revoke-audit columns excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO vpn_node_assignment \
            (config_id, scope_type, target_node_id, target_domain, service_slug, state, \
             assigned_by, assigned_at, domain, propagation_state, generation) \
            VALUES (:config_id, :scope_type, :target_node_id, :target_domain, :service_slug, \
             :state, :assigned_by, :assigned_at, :domain, :propagation_state, :generation) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("config_id") String configId,
                                   @Param("scope_type") String scopeType,
                                   @Param("target_node_id") String targetNodeId,
                                   @Param("target_domain") String targetDomain,
                                   @Param("service_slug") String serviceSlug,
                                   @Param("state") String state,
                                   @Param("assigned_by") String assignedBy,
                                   @Param("assigned_at") Instant assignedAt,
                                   @Param("domain") String domain,
                                   @Param("propagation_state") String propagationState,
                                   @Param("generation") long generation);

    Flux<VpnNodeAssignmentRow> findByDomainOrderByAssignedAtDesc(String domain);

    Flux<VpnNodeAssignmentRow> findAllByOrderByDomainAscAssignedAtDesc();

    Flux<VpnNodeAssignmentRow> findByStateOrderByDomainAscAssignedAtAsc(String state);

    Flux<VpnNodeAssignmentRow> findByStateAndScopeTypeAndTargetNodeId(
            String state, String scopeType, String targetNodeId);

    /** Active DEVICE assignment for (target_node_id, service_slug) with COALESCE('*') match. */
    String FIND_ACTIVE_NODE =
            "SELECT * FROM vpn_node_assignment WHERE scope_type = 'DEVICE' AND target_node_id = :node "
            + "AND COALESCE(service_slug, '*') = COALESCE(:svc, '*') AND state = 'active'";

    @Query(FIND_ACTIVE_NODE)
    Mono<VpnNodeAssignmentRow> findActiveNode(String node, String svc);

    /** Active DOMAIN assignment for (target_domain, service_slug) with COALESCE('*') match. */
    String FIND_ACTIVE_DOMAIN =
            "SELECT * FROM vpn_node_assignment WHERE scope_type = 'DOMAIN' AND target_domain = :td "
            + "AND COALESCE(service_slug, '*') = COALESCE(:svc, '*') AND state = 'active'";

    @Query(FIND_ACTIVE_DOMAIN)
    Mono<VpnNodeAssignmentRow> findActiveDomain(String td, String svc);

    String MAX_GENERATION = "SELECT COALESCE(MAX(generation), 0) AS g FROM vpn_node_assignment";

    @Query(MAX_GENERATION)
    Mono<Long> maxGeneration();

    String REVOKE_SCOPED =
            "UPDATE vpn_node_assignment SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active' AND domain = :domain";

    @Modifying
    @Query(REVOKE_SCOPED)
    Mono<Long> revokeScoped(String id, String by, long gen, String domain);

    String REVOKE_UNSCOPED =
            "UPDATE vpn_node_assignment SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(REVOKE_UNSCOPED)
    Mono<Long> revokeUnscoped(String id, String by, long gen);

    String REVOKE_BY_CONFIG =
            "UPDATE vpn_node_assignment SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "generation = :gen, propagation_state = 'pending' "
            + "WHERE config_id = :cfg AND state = 'active'";

    @Modifying
    @Query(REVOKE_BY_CONFIG)
    Mono<Long> revokeByConfig(String cfg, String by, long gen);

    String UPDATE_PROP = "UPDATE vpn_node_assignment SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);
}
