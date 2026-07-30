package systems.hugmesh.adminbff.golive;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code go_live_intent} (changeset 270). All queries
 * are UNSCOPED — go-live is cross-domain infra, gated SUPERADMIN-only at the controller
 * (mirrors {@link systems.hugmesh.adminbff.domainregistry.DomainRegistryRowRepository}).
 *
 * <p>DB-GENERATED PK (the changelog-200 idiom): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id}. Mutations are explicit CAS UPDATEs (never {@code save()}); a row is
 * NEVER deleted — withdraw is a CAS {@code recorded->withdrawn} audit transition.
 */
public interface GoLiveIntentRowRepository extends ReactiveCrudRepository<GoLiveIntentRow, String> {

    /**
     * Insert a new RECORDED intent with a DB-generated id. {@code status} takes its DB
     * DEFAULT {@code 'recorded'}; {@code applied_at}/{@code applied_by} stay NULL (the host
     * agent's ack surface — the BFF NEVER supplies them). {@code generation} is the caller's
     * pre-computed {@code max(generation)+1} stamp (the 011 monotonic idiom).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO go_live_intent \
            (cluster_domain, target_state, exposure_model, provider, note, \
             requested_by_subject, created_at, updated_at, generation) \
            VALUES (:cluster_domain, :target_state, :exposure_model, :provider, :note, \
             :requested_by_subject, :created_at, :updated_at, :generation) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("cluster_domain") String clusterDomain,
                                   @Param("target_state") String targetState,
                                   @Param("exposure_model") String exposureModel,
                                   @Param("provider") String provider,
                                   @Param("note") String note,
                                   @Param("requested_by_subject") String requestedBySubject,
                                   @Param("created_at") Instant createdAt,
                                   @Param("updated_at") Instant updatedAt,
                                   @Param("generation") long generation);

    /** Full wizard history, newest first (rows are never deleted — the audit view). */
    Flux<GoLiveIntentRow> findAllByOrderByCreatedAtDesc();

    /** All rows in one status ({@code recorded} = the export compile source), natural-key
     *  ordered so the canonical export bytes are reproducible. */
    Flux<GoLiveIntentRow> findByStatusOrderByClusterDomain(String status);

    /** The active ({@code recorded}) intents targeting one domain (the supersede check). */
    Flux<GoLiveIntentRow> findByClusterDomainAndStatus(String clusterDomain, String status);

    /** Monotonic table-wide generation floor: every BFF mutation stamps max+1 so the signed
     *  export STRICTLY advances even when a withdraw removes a row from the compiled body. */
    @Query("SELECT COALESCE(MAX(generation), 0) FROM go_live_intent")
    Mono<Long> maxGeneration();

    /**
     * CAS withdraw: {@code recorded -> withdrawn} (never a DELETE — audit). Guarded on the
     * current status so a concurrent double-withdraw / a withdraw racing the host agent's
     * {@code applied} ack has a single winner. Returns rows updated (1 won, 0 lost/absent).
     */
    @Modifying
    @Query("""
            UPDATE go_live_intent \
            SET status = 'withdrawn', updated_at = :now, generation = :generation \
            WHERE id = :id AND status = 'recorded'""")
    Mono<Long> withdraw(@Param("id") String id,
                        @Param("now") Instant now,
                        @Param("generation") long generation);

    /**
     * HOST-AGENT applied-ack: CAS {@code recorded -> applied}, stamping {@code applied_at}/
     * {@code applied_by} (the ONE write path for those two columns — the BFF's own record/
     * withdraw paths never touch them). Guarded on BOTH {@code id} AND the row's OWN {@code
     * generation} — see {@link GoLiveService#applyAck} for why the generation bind matters
     * (it is the intent's own per-row stamp, NOT the export envelope's top-level max-over-all-
     * rows generation). Returns rows updated (1 = applied now, 0 = lost/absent/stale: already
     * applied, already withdrawn, or superseded by a newer intent under a different id — all a
     * normal idempotent no-op for a host agent retrying every reconcile cycle).
     */
    @Modifying
    @Query("""
            UPDATE go_live_intent \
            SET status = 'applied', updated_at = :now, applied_at = :now, applied_by = :appliedBy \
            WHERE id = :id AND status = 'recorded' AND generation = :generation""")
    Mono<Long> markApplied(@Param("id") String id,
                           @Param("now") Instant now,
                           @Param("appliedBy") String appliedBy,
                           @Param("generation") long generation);
}
