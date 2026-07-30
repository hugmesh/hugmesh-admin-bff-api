package systems.hugmesh.adminbff.servicecatalog;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code app_profile} — the reusable, SUPERADMIN-owned deploy
 * templates (schema in Liquibase {@code db/changelog/101-app-profile.xml}). App-generated
 * {@code varchar(36)} UUID ids, never a blocking call.
 *
 * <p>Backed by the Spring Data {@link AppProfileR2dbcRepository} (no raw {@code DatabaseClient});
 * maps the {@link AppProfileRow} entity to/from the {@link AppProfile} domain record.
 *
 * <p>app_profile is a GLOBAL library (NO per-row tenant discriminator) — every query is
 * UNSCOPED; the controller's {@code @PreAuthorize("hasRole('SUPERADMIN')")} is the only
 * gate. {@code name} is the UNIQUE natural key, so a duplicate surfaces as the DB
 * unique-violation the service treats as a 409. {@code profile_json} is opaque template
 * data read/written as a String.
 */
@Repository
public class AppProfileRepository {

    private final AppProfileR2dbcRepository repo;

    public AppProfileRepository(AppProfileR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * Insert a new profile (app-generated id), stamping {@code created_by_subject} and
     * returning the persisted row. {@code name} is the UNIQUE natural key, so a duplicate
     * surfaces as the DB unique-violation the service maps to a 409 (the caller is expected
     * to have run the {@link #findByName} idempotency check first; the UNIQUE index is the
     * backstop against a race).
     */
    public Mono<AppProfile> insert(String name, String profileJson, String createdBySubject) {
        Instant now = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id hands back the generated string, mapped into the persisted
        // AppProfile with the SAME field order/values as before. A duplicate name still surfaces
        // as the DB unique-violation the service maps to a 409 (no ON CONFLICT).
        return repo.insertReturningId(name, profileJson, createdBySubject, now, now)
                .map(genId -> new AppProfile(genId, name, profileJson, createdBySubject, now, now));
    }

    /** Every profile (the SUPERADMIN list surface), ordered by name. */
    public Flux<AppProfile> findAll() {
        return repo.findByOrderByName().map(AppProfileRow::toDomain);
    }

    /** The profile with this {@code name}, if any — the natural-key lookup the create
     *  idempotency check + the get-by-name endpoint use. */
    public Mono<AppProfile> findByName(String name) {
        return repo.findByName(name).map(AppProfileRow::toDomain);
    }

    /**
     * Update the mutable {@code profile_json} of an existing profile (matched by
     * {@code name}) and re-read the row. The PK ({@code id}), the {@code name} natural key,
     * {@code created_at} and {@code created_by_subject} are IMMUTABLE; {@code updated_at} is
     * bumped. Returns the updated row, or empty if no profile with that {@code name} exists.
     */
    public Mono<AppProfile> updateJson(String name, String profileJson) {
        return repo.updateJson(name, profileJson)
                .flatMap(n -> n == 0 ? Mono.empty() : findByName(name));
    }

    /** Hard-delete a profile by {@code name} (a reusable template is a library entry the
     *  superadmin may remove); returns the rows-deleted count (0 = no such profile). */
    public Mono<Long> deleteByName(String name) {
        return repo.deleteByNameReturningCount(name);
    }
}
