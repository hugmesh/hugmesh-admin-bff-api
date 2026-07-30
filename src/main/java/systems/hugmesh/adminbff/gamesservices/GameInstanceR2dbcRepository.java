package systems.hugmesh.adminbff.gamesservices;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Collection;

/**
 * Reactive (R2DBC) Spring Data store for {@code game_instance} (changeset 091). The by-id /
 * scoped reads, the non-terminal lookups (a {@code state IN (:states)} derived finder, the
 * literal non-terminal set is supplied by the facade), the admin lists, and the per-domain
 * active scan are derived finders; the DISTINCT-domain scan, the scalar node-port projection,
 * the TTL-expiry scan, the generic CAS-state UPDATE, the propagation-state UPDATE, and the two
 * guarded partial assigns are {@code @Query} static-final constants (DISTINCT, scalar
 * projections, a CAS-on-state set, and NULL-guarded partial UPDATEs are not derivable). The
 * {@link GameInstanceRepository} facade maps rows to/from the {@link GameInstance} domain
 * record.
 */
public interface GameInstanceR2dbcRepository
        extends ReactiveCrudRepository<GameInstanceRow, String> {

    /**
     * Insert a new PENDING instance with a DB-generated id (changelog 200): {@code id} is
     * OMITTED → filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code
     * RETURNING id} reads the generated varchar(36) back ({@code Mono<String>}). The
     * not-yet-assigned {@code namespace}/{@code node_port}/{@code console_path} are OMITTED
     * (default NULL — the fresh-instance shape; the reconcile loop assigns them later). The
     * supplied columns match the {@link GameInstanceRow} column order (id + the three
     * later-assigned columns excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO game_instance \
            (domain, slug, name, state, propagation_state, owner_subject, created_at, \
             ending_at, updated_at) \
            VALUES (:domain, :slug, :name, :state, :propagation_state, :owner_subject, \
             :created_at, :ending_at, :updated_at) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("slug") String slug,
                                   @Param("name") String name,
                                   @Param("state") String state,
                                   @Param("propagation_state") String propagationState,
                                   @Param("owner_subject") String ownerSubject,
                                   @Param("created_at") Instant createdAt,
                                   @Param("ending_at") Instant endingAt,
                                   @Param("updated_at") Instant updatedAt);

    /** A single instance by id within a brand (scoped resolve). */
    Mono<GameInstanceRow> findByIdAndDomain(String id, String domain);

    /** The non-terminal instance for a (domain, slug, name), if any — the idempotency check. */
    Mono<GameInstanceRow> findByDomainAndSlugAndNameAndStateIn(
            String domain, String slug, String name, Collection<String> states);

    /** Count NON-TERMINAL instances for a (domain, slug) — the quota check. */
    Mono<Long> countByDomainAndSlugAndStateIn(String domain, String slug, Collection<String> states);

    /** All instances for a brand, by (slug, name) — the scoped admin read. */
    Flux<GameInstanceRow> findByDomainOrderBySlugAscNameAsc(String domain);

    /** ALL instances (unscoped SUPERADMIN), domain then (slug, name). */
    Flux<GameInstanceRow> findByOrderByDomainAscSlugAscNameAsc();

    /** All instances in a state for a domain, by (slug, name) — the ConfigMap render set. */
    Flux<GameInstanceRow> findByDomainAndStateOrderBySlugAscNameAsc(String domain, String state);

    /** Every domain with at least one instance in the given state (the render targets). */
    String DOMAINS_IN_STATE =
            "SELECT DISTINCT domain FROM game_instance WHERE state = :state ORDER BY domain";

    @Query(DOMAINS_IN_STATE)
    Flux<String> domainsInState(String state);

    /** ACTIVE instances whose TTL has passed (NULL TTL never expires). */
    String DUE_FOR_EXPIRY =
            "SELECT id, domain, slug, name, state, propagation_state, owner_subject, created_at, "
            + "ending_at, namespace, node_port, console_path, updated_at FROM game_instance "
            + "WHERE state = 'active' AND ending_at IS NOT NULL AND ending_at <= :now "
            + "ORDER BY ending_at";

    @Query(DUE_FOR_EXPIRY)
    Flux<GameInstanceRow> dueForExpiry(Instant now);

    /** Every node_port held by a non-terminal instance — the allocator's in-use set. */
    String ALLOCATED_NODE_PORTS =
            "SELECT node_port FROM game_instance "
            + "WHERE node_port IS NOT NULL AND state IN ('pending','active','suspended')";

    @Query(ALLOCATED_NODE_PORTS)
    Flux<Integer> allocatedNodePorts();

    /** CAS to a new state for one id, guarded on the current-state set (one writer wins). */
    String CAS_STATE =
            "UPDATE game_instance SET state = :toState, updated_at = now() "
            + "WHERE id = :id AND state IN (:fromStates)";

    @Modifying
    @Query(CAS_STATE)
    Mono<Long> casState(String id, String toState, Collection<String> fromStates);

    /** Record the ConfigMap-render-leg outcome (pending/applied/failed) for a row. */
    String UPDATE_PROP = "UPDATE game_instance SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);

    /** Assign node_port + console_path, guarded so it only writes when node_port is NULL. */
    String ASSIGN_PORT =
            "UPDATE game_instance SET node_port = :np, console_path = :cp, updated_at = now() "
            + "WHERE id = :id AND node_port IS NULL";

    @Modifying
    @Query(ASSIGN_PORT)
    Mono<Long> assignPortAndConsole(String id, int np, String cp);

    /** Assign the namespace, guarded so it only writes when namespace is NULL. */
    String ASSIGN_NAMESPACE =
            "UPDATE game_instance SET namespace = :ns, updated_at = now() "
            + "WHERE id = :id AND namespace IS NULL";

    @Modifying
    @Query(ASSIGN_NAMESPACE)
    Mono<Long> assignNamespace(String id, String ns);
}
