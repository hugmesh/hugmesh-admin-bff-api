package systems.hugmesh.adminbff.servicecatalog;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code service_deployment} (changeset 102). The
 * per-domain and scoped/unscoped lists are derived finders; the TTL-expiry scan, the
 * state-guarded CAS end UPDATE, and the propagation-state partial UPDATE are {@code @Query}
 * static-final constants (a NULL-guarded TTL scan and CAS-on-state UPDATEs are not derivable).
 * The {@link ServiceDeploymentRepository} facade maps rows to/from the {@link ServiceDeployment}
 * domain record.
 */
public interface ServiceDeploymentR2dbcRepository
        extends ReactiveCrudRepository<ServiceDeploymentRow, String> {

    /**
     * Insert a new ACTIVE deployment with a DB-generated id (changelog 200): {@code id} is OMITTED
     * → filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads
     * the generated varchar(36) back ({@code Mono<String>}). The not-yet-set {@code ended_at} is
     * OMITTED (default NULL — the fresh-deployment shape). Columns match the
     * {@link ServiceDeploymentRow} order (id + ended_at excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO service_deployment \
            (domain, service_key, profile_ref, state, created_at, ending_at, enforce_actions, \
             propagation_state, created_by_subject) \
            VALUES (:domain, :serviceKey, :profileRef, :state, :createdAt, :endingAt, \
             :enforceActions, :propagationState, :createdBySubject) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("serviceKey") String serviceKey,
                                   @Param("profileRef") String profileRef,
                                   @Param("state") String state,
                                   @Param("createdAt") Instant createdAt,
                                   @Param("endingAt") Instant endingAt,
                                   @Param("enforceActions") String enforceActions,
                                   @Param("propagationState") String propagationState,
                                   @Param("createdBySubject") String createdBySubject);

    /** Deployments for a domain, newest first — the per-domain / scoped list. */
    Flux<ServiceDeploymentRow> findByDomainOrderByCreatedAtDesc(String domain);

    /** ALL deployments (unscoped SUPERADMIN), domain then newest first. */
    Flux<ServiceDeploymentRow> findByOrderByDomainAscCreatedAtDesc();

    /** ACTIVE deployments whose ending_at clock has passed (NULL never expires). */
    String DUE_FOR_ENDING =
            "SELECT id, domain, service_key, profile_ref, state, created_at, ending_at, "
            + "enforce_actions, propagation_state, ended_at, created_by_subject "
            + "FROM service_deployment "
            + "WHERE state = 'active' AND ending_at IS NOT NULL AND ending_at <= :now "
            + "ORDER BY ending_at";

    @Query(DUE_FOR_ENDING)
    Flux<ServiceDeploymentRow> dueForEnding(Instant now);

    /** CAS {@code active -> ended} for one id, stamping {@code ended_at}. */
    String MARK_ENDED =
            "UPDATE service_deployment SET state = 'ended', ended_at = now() "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(MARK_ENDED)
    Mono<Long> markEnded(String id);

    /** Record the enforce-actions leg outcome (pending/applied/failed) for a row. */
    String UPDATE_PROP = "UPDATE service_deployment SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);
}
