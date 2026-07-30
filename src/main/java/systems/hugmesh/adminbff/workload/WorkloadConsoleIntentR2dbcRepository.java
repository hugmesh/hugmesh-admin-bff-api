package systems.hugmesh.adminbff.workload;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code workload_console_intent} (changeset 110). The
 * pending scoped/unscoped lists are derived finders; the {@code MAX(generation)} aggregate is a
 * {@code @Query} static-final constant. The {@link WorkloadConsoleIntentRepository} facade maps
 * rows to/from the {@link WorkloadConsoleIntent} domain record.
 */
public interface WorkloadConsoleIntentR2dbcRepository
        extends ReactiveCrudRepository<WorkloadConsoleIntentRow, String> {

    /**
     * Insert a new intent with a DB-generated id (changelog 200): {@code id} is OMITTED → filled
     * from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads the
     * generated varchar(36) back ({@code Mono<String>}). Columns match the
     * {@link WorkloadConsoleIntentRow} order (id excluded); the nullable {@code replicas} /
     * {@code image_ref} are passed through as supplied.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO workload_console_intent \
            (kind, namespace, workload, image_ref, replicas, requested_by, requested_at, domain, \
             propagation_state, generation) \
            VALUES (:kind, :namespace, :workload, :imageRef, :replicas, :requestedBy, \
             :requestedAt, :domain, :propagationState, :generation) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("kind") String kind,
                                   @Param("namespace") String namespace,
                                   @Param("workload") String workload,
                                   @Param("imageRef") String imageRef,
                                   @Param("replicas") Integer replicas,
                                   @Param("requestedBy") String requestedBy,
                                   @Param("requestedAt") Instant requestedAt,
                                   @Param("domain") String domain,
                                   @Param("propagationState") String propagationState,
                                   @Param("generation") long generation);

    /** Pending intents for a brand, newest first — the scoped "pending sync" surface. */
    Flux<WorkloadConsoleIntentRow> findByPropagationStateAndDomainOrderByRequestedAtDesc(
            String propagationState, String domain);

    /** ALL pending intents (unscoped SUPERADMIN), newest first. */
    Flux<WorkloadConsoleIntentRow> findByPropagationStateOrderByRequestedAtDesc(
            String propagationState);

    /** The current MAX(generation) across ALL intent rows; 0 when empty. */
    String MAX_GENERATION = "SELECT COALESCE(MAX(generation), 0) FROM workload_console_intent";

    @Query(MAX_GENERATION)
    Mono<Long> maxGeneration();
}
