package systems.hugmesh.adminbff.phone;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code fleet_entitlement} (Liquibase changeset 306) —
 * the per-subject FLEET-ADMIN subscription gate. The PK is the natural {@code subject} varchar,
 * so the upsert is a hand-written UPDATE-then-INSERT (Spring Data cannot tell insert from update
 * for a caller-supplied string PK without {@code Persistable}); {@link FleetEntitlementService}
 * composes them. The entitlement CHECK is a fail-closed count against the DB clock.
 */
public interface FleetEntitlementRowRepository extends ReactiveCrudRepository<FleetEntitlementRow, String> {

    /**
     * Fail-closed entitlement count: rows for {@code subject} that are ACTIVE and unexpired
     * ({@code expires_at IS NULL OR expires_at > now()}), evaluated against the Postgres clock
     * (never the JVM clock). 0 when there is no row, the row is inactive, or it has expired —
     * the {@link FleetEntitlementService} maps {@code > 0} to entitled.
     */
    String COUNT_ENTITLED = """
            SELECT count(*) FROM fleet_entitlement \
            WHERE subject = :subject AND active = true \
            AND (expires_at IS NULL OR expires_at > now())""";

    @Query(COUNT_ENTITLED)
    Mono<Long> countEntitled(@Param("subject") String subject);

    /** Update an existing entitlement (rows-updated: 0 means no row to upsert into yet). */
    String UPDATE_ENTITLEMENT = """
            UPDATE fleet_entitlement SET active = :active, seats = :seats, \
            expires_at = :expiresAt, updated_at = now() \
            WHERE subject = :subject""";

    @Modifying
    @Query(UPDATE_ENTITLEMENT)
    Mono<Long> updateEntitlement(@Param("subject") String subject, @Param("active") boolean active,
                                 @Param("seats") Integer seats, @Param("expiresAt") Instant expiresAt);

    /** Insert a first entitlement; {@code updated_at} takes the column now() default. */
    String INSERT_ENTITLEMENT = """
            INSERT INTO fleet_entitlement (subject, active, seats, expires_at) \
            VALUES (:subject, :active, :seats, :expiresAt)""";

    @Modifying
    @Query(INSERT_ENTITLEMENT)
    Mono<Long> insertEntitlement(@Param("subject") String subject, @Param("active") boolean active,
                                 @Param("seats") Integer seats, @Param("expiresAt") Instant expiresAt);

    /** Revoke an entitlement outright (rows-deleted: 0 when the subject had none). */
    String DELETE_ENTITLEMENT = "DELETE FROM fleet_entitlement WHERE subject = :subject";

    @Modifying
    @Query(DELETE_ENTITLEMENT)
    Mono<Long> deleteEntitlement(@Param("subject") String subject);

    /** All entitlements, subject-ordered (the superadmin list). */
    Flux<FleetEntitlementRow> findAllByOrderBySubjectAsc();
}
