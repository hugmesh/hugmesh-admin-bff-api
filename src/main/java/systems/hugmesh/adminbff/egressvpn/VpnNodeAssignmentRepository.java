package systems.hugmesh.adminbff.egressvpn;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code vpn_node_assignment} — the explicit (config x
 * NODE|DOMAIN) assignment rows (schema in Liquibase {@code db/changelog/080-egress-vpn-
 * configs.xml}).
 *
 * <p>Backed by the Spring Data {@link VpnNodeAssignmentRowRepository} (no raw
 * {@code DatabaseClient}); maps the {@link VpnNodeAssignmentRow} entity to the
 * {@link VpnNodeAssignment} domain record. Idempotency lookups COALESCE service_slug to a
 * '*' "all" row; revoke is a CAS {@code active -> revoked} at a monotonic generation that
 * NEVER deletes (the row is the audit trail).
 */
@Repository
public class VpnNodeAssignmentRepository {

    private final VpnNodeAssignmentRowRepository repo;

    public VpnNodeAssignmentRepository(VpnNodeAssignmentRowRepository repo) {
        this.repo = repo;
    }

    /** The active DEVICE assignment for (target_node_id, service_slug), if any. */
    public Mono<VpnNodeAssignment> findActiveNode(String targetNodeId, String serviceSlug) {
        return repo.findActiveNode(targetNodeId, serviceSlug == null ? "*" : serviceSlug)
                .map(VpnNodeAssignmentRow::toDomain);
    }

    /** The active DOMAIN assignment for (target_domain, service_slug), if any. */
    public Mono<VpnNodeAssignment> findActiveDomain(String targetDomain, String serviceSlug) {
        return repo.findActiveDomain(targetDomain, serviceSlug == null ? "*" : serviceSlug)
                .map(VpnNodeAssignmentRow::toDomain);
    }

    /** Insert a new ACTIVE assignment (DB-generated id) at the given monotonic generation. The
     *  INSERT omits {@code id} (filled from the {@code (gen_random_uuid())::text} column
     *  DEFAULT, changelog 200) and {@code RETURNING id} hands back the generated string, which
     *  we read back by that id to return the persisted row (same field order/values as
     *  before; the freshly-inserted row's revoke-audit columns are NULL). */
    public Mono<VpnNodeAssignment> insertActive(VpnNodeAssignment a, long generation) {
        return repo.insertReturningId(a.configId(), a.scopeType(), a.targetNodeId(),
                        a.targetDomain(), a.serviceSlug(), VpnNodeAssignment.STATE_ACTIVE,
                        a.assignedBy(), Instant.now(), a.domain(), VpnNodeAssignment.PROP_PENDING,
                        generation)
                .flatMap(genId -> repo.findById(genId).map(VpnNodeAssignmentRow::toDomain));
    }

    /** ALL assignments VISIBLE to the given tenant scope — the ADMIN read surface. */
    public Flux<VpnNodeAssignment> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByAssignedAtDesc(domain).map(VpnNodeAssignmentRow::toDomain);
        }
        return repo.findAllByOrderByDomainAscAssignedAtDesc().map(VpnNodeAssignmentRow::toDomain);
    }

    /** ALL active assignments (every brand). UNSCOPED — the signed export's working set (PR5). */
    public Flux<VpnNodeAssignment> listActiveAll() {
        return repo.findByStateOrderByDomainAscAssignedAtAsc(VpnNodeAssignment.STATE_ACTIVE)
                .map(VpnNodeAssignmentRow::toDomain);
    }

    /** Active assignments targeting one node fp. UNSCOPED — the per-node export shape (PR5). */
    public Flux<VpnNodeAssignment> activeForNode(String targetNodeId) {
        return repo.findByStateAndScopeTypeAndTargetNodeId(
                        VpnNodeAssignment.STATE_ACTIVE, "DEVICE", targetNodeId)
                .map(VpnNodeAssignmentRow::toDomain);
    }

    public Mono<VpnNodeAssignment> findById(String id) {
        return repo.findById(id).map(VpnNodeAssignmentRow::toDomain);
    }

    public Mono<Long> maxGeneration() {
        return repo.maxGeneration().defaultIfEmpty(0L);
    }

    /** CAS {@code active -> revoked} for one assignment id at a NEW generation. */
    public Mono<Long> revoke(String id, String revokedBy, long newGeneration, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.revokeScoped(id, revokedBy, newGeneration, domain);
        }
        return repo.revokeUnscoped(id, revokedBy, newGeneration);
    }

    /** Revoke ALL active assignments referencing a config (cascade) at a NEW generation. */
    public Mono<Long> revokeByConfig(String configId, String revokedBy, long newGeneration) {
        return repo.revokeByConfig(configId, revokedBy, newGeneration);
    }
}
