package net.hugmesh.adminbff.matrixadmin;

import java.time.Instant;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) store for {@code matrix_admin_deactivate_proposal} (changeset 370).
 *
 * <p>Why a table and not an in-memory map: admin-bff runs behind an HPA with
 * {@code minReplicas: 2} (hugmesh-generator specs/cluster/manifests/admin-bff-api/hpa.yaml), so
 * the propose and the confirm can land on DIFFERENT replicas. A per-process map would refuse
 * roughly half of all legitimate confirms, and a leader-pinned one (the
 * {@code WorkloadStepUpService} shape) still cannot see a propose served by a follower. The
 * single-use property is enforced by {@link #consume}, a compare-and-swap that exactly one
 * concurrent confirm can win on any replica.
 */
public interface MatrixDeactivateProposalRepository
        extends ReactiveCrudRepository<MatrixDeactivateProposalRow, String> {

    /** The proposal a presented token belongs to (by SHA-256; the raw token is never stored). */
    Mono<MatrixDeactivateProposalRow> findByTokenHash(String tokenHash);

    /**
     * CAS {@code proposed -> confirmed}. Every binding is re-asserted in the WHERE so a row
     * read a moment earlier cannot be confirmed if it changed or expired in between: 1 = this
     * caller won, 0 = refused (already used, expired, another admin's, another account's).
     */
    @Modifying
    @Query("UPDATE matrix_admin_deactivate_proposal "
            + "SET state = 'confirmed', confirmed_at = :now "
            + "WHERE id = :id AND state = 'proposed' AND expires_at > :now "
            + "AND proposed_by = :proposedBy AND mxid = :mxid")
    Mono<Long> consume(String id, String proposedBy, String mxid, Instant now);

    /** Stamp the transport outcome on a confirmed row (audit). */
    @Modifying
    @Query("UPDATE matrix_admin_deactivate_proposal SET outcome = :outcome "
            + "WHERE id = :id AND state = 'confirmed'")
    Mono<Long> recordOutcome(String id, String outcome);
}
