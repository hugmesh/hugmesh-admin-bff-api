package systems.hugmesh.adminbff.servicecatalog.scaffold;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code service_scaffold} (changeset 320). The insert is
 * an {@code INSERT ... RETURNING id} {@code @Query} (DB-generated id, the 100/102 convention); the
 * per-domain list is a derived finder; the state-guarded CAS {@code requested -> archived} UPDATE
 * is a {@code @Query} constant. The {@link ServiceScaffoldRepository} facade maps rows to/from the
 * {@link ServiceScaffold} domain record.
 */
public interface ServiceScaffoldR2dbcRepository
        extends ReactiveCrudRepository<ServiceScaffoldRow, String> {

    /**
     * Insert a new {@code requested} scaffold with a DB-generated id (changelog 320): {@code id} is
     * OMITTED → filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING
     * id} reads the generated varchar(36) back. Columns match the {@link ServiceScaffoldRow} order
     * (id excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO service_scaffold \
            (domain, service_key, archetype, display_name, mount_at, requires_role, state, \
             created_by_subject, created_at, updated_at) \
            VALUES (:domain, :serviceKey, :archetype, :displayName, :mountAt, :requiresRole, :state, \
             :createdBySubject, :createdAt, :updatedAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(String domain, String serviceKey, String archetype,
                                   String displayName, String mountAt, String requiresRole,
                                   String state, String createdBySubject, Instant createdAt,
                                   Instant updatedAt);

    /** Every scaffold for an EXPLICIT {@code domain} (the superadmin per-domain view), newest first. */
    Flux<ServiceScaffoldRow> findByDomainOrderByCreatedAtDesc(String domain);

    /** CAS {@code requested -> archived} for one id, bumping {@code updated_at}. Returns the
     *  rows-updated count (1 = this call materialised it first, 0 = already archived). */
    String MARK_ARCHIVED =
            "UPDATE service_scaffold SET state = 'archived', updated_at = now() "
            + "WHERE id = :id AND state = 'requested'";

    @Modifying
    @Query(MARK_ARCHIVED)
    Mono<Long> markArchived(String id);
}
