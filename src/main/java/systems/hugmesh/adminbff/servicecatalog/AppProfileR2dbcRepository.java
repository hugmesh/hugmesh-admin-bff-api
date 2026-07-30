package systems.hugmesh.adminbff.servicecatalog;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code app_profile} (changeset 101). The list and
 * by-name lookup are derived finders; the by-name partial UPDATE (bumps {@code updated_at})
 * and the by-name DELETE returning a count are {@code @Query} static-final constants. The
 * {@link AppProfileRepository} facade maps rows to/from the {@link AppProfile} domain record.
 */
public interface AppProfileR2dbcRepository
        extends ReactiveCrudRepository<AppProfileRow, String> {

    /**
     * Insert a new profile with a DB-generated id (changelog 200): {@code id} is OMITTED → filled
     * from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads the
     * generated varchar(36) back ({@code Mono<String>}). {@code name} is the UNIQUE natural key —
     * a PLAIN INSERT (no ON CONFLICT) so a duplicate still surfaces as the DB unique-violation the
     * service maps to a 409. Columns match the {@link AppProfileRow} order (id excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO app_profile \
            (name, profile_json, created_by_subject, created_at, updated_at) \
            VALUES (:name, :profileJson, :createdBySubject, :createdAt, :updatedAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("name") String name,
                                   @Param("profileJson") String profileJson,
                                   @Param("createdBySubject") String createdBySubject,
                                   @Param("createdAt") Instant createdAt,
                                   @Param("updatedAt") Instant updatedAt);

    /** Every profile, ordered by name — the SUPERADMIN list surface. */
    Flux<AppProfileRow> findByOrderByName();

    /** The profile with this {@code name}, if any — the natural-key lookup. */
    Mono<AppProfileRow> findByName(String name);

    /** Update the mutable {@code profile_json} of the profile matched by {@code name}. */
    String UPDATE_JSON =
            "UPDATE app_profile SET profile_json = :profileJson, updated_at = now() "
            + "WHERE name = :name";

    @Modifying
    @Query(UPDATE_JSON)
    Mono<Long> updateJson(String name, String profileJson);

    /** Hard-delete the profile by {@code name}; returns the rows-deleted count. */
    String DELETE_BY_NAME = "DELETE FROM app_profile WHERE name = :name";

    @Modifying
    @Query(DELETE_BY_NAME)
    Mono<Long> deleteByNameReturningCount(String name);
}
