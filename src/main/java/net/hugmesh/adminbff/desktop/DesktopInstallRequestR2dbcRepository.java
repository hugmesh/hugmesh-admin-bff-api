package net.hugmesh.adminbff.desktop;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code desktop_install_request} (changeset 140). The
 * double-scoped user reads, the scoped/unscoped admin reads, and the scoped by-id read are
 * derived finders; the two state-guarded scoped/unscoped CAS decide UPDATEs are {@code @Query}
 * static-final constants (a CAS-on-status stamping UPDATE is not derivable). The
 * {@link DesktopInstallRequestRepository} facade maps rows to/from the
 * {@link DesktopInstallRequest} domain record.
 */
public interface DesktopInstallRequestR2dbcRepository
        extends ReactiveCrudRepository<DesktopInstallRequestRow, String> {

    /**
     * Insert a new PENDING request with a DB-generated id (changelog 200): {@code id} is OMITTED →
     * filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads
     * the generated varchar(36) back ({@code Mono<String>}). The not-yet-set {@code decided_by}/
     * {@code decided_at} are OMITTED (default NULL — the fresh-request shape). Columns match the
     * {@link DesktopInstallRequestRow} order (id + decided_by + decided_at excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO desktop_install_request \
            (requester, app_ref, device_id, status, domain, created_at) \
            VALUES (:requester, :appRef, :deviceId, :status, :domain, :createdAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("requester") String requester,
                                   @Param("appRef") String appRef,
                                   @Param("deviceId") String deviceId,
                                   @Param("status") String status,
                                   @Param("domain") String domain,
                                   @Param("createdAt") Instant createdAt);

    /** The requester's OWN requests in their OWN brand, newest first (cross-user isolation). */
    Flux<DesktopInstallRequestRow> findByRequesterAndDomainOrderByCreatedAtDesc(
            String requester, String domain);

    /** One of the requester's own requests by id (double-scoped — invisible to others). */
    Mono<DesktopInstallRequestRow> findByIdAndRequesterAndDomain(
            String id, String requester, String domain);

    /** Requests for a brand, newest first — the scoped admin inbox. */
    Flux<DesktopInstallRequestRow> findByDomainOrderByCreatedAtDesc(String domain);

    /** ALL requests (unscoped SUPERADMIN), domain then newest first. */
    Flux<DesktopInstallRequestRow> findByOrderByDomainAscCreatedAtDesc();

    /** One request by id within a brand (scoped resolve). */
    Mono<DesktopInstallRequestRow> findByIdAndDomain(String id, String domain);

    /** CAS {@code pending -> newStatus} for one request in a brand, stamping the decider. */
    String DECIDE_SCOPED =
            "UPDATE desktop_install_request "
            + "SET status = :st, decided_by = :by, decided_at = now() "
            + "WHERE id = :id AND status = 'pending' AND domain = :domain";

    @Modifying
    @Query(DECIDE_SCOPED)
    Mono<Long> decideScoped(String id, String st, String by, String domain);

    /** CAS {@code pending -> newStatus} for one request (unscoped SUPERADMIN). */
    String DECIDE_ALL =
            "UPDATE desktop_install_request "
            + "SET status = :st, decided_by = :by, decided_at = now() "
            + "WHERE id = :id AND status = 'pending'";

    @Modifying
    @Query(DECIDE_ALL)
    Mono<Long> decideAll(String id, String st, String by);
}
