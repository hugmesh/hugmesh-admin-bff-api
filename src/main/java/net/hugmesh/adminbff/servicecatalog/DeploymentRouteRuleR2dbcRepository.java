package net.hugmesh.adminbff.servicecatalog;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Reactive (R2DBC) Spring Data store for {@code service_deployment_route_rule} (changeset 400).
 * The reads are derived finders; the INSERT and the {@code removed_at} stamp are {@code @Query}
 * static-final constants. The {@link DeploymentRouteRuleRepository} facade is the only caller.
 */
public interface DeploymentRouteRuleR2dbcRepository
        extends ReactiveCrudRepository<DeploymentRouteRuleRow, UUID> {

    /** Record that {@code deploymentId}'s provision wrote the rule {@code ruleId}. A PLAIN
     *  INSERT: {@code rule_id} is the primary key, so recording one rule twice is an error, not
     *  a silent second owner. {@code recorded_at} is the column DEFAULT {@code now()}. */
    String INSERT =
            "INSERT INTO service_deployment_route_rule (rule_id, deployment_id) "
            + "VALUES (:ruleId, :deploymentId)";

    @Modifying
    @Query(INSERT)
    Mono<Long> insert(@Param("ruleId") UUID ruleId, @Param("deploymentId") String deploymentId);

    /** The rules that are still {@code deploymentId}'s (not yet removed), oldest first. */
    Flux<DeploymentRouteRuleRow> findByDeploymentIdAndRemovedAtIsNullOrderByRecordedAt(String deploymentId);

    /** True once ANY rule was ever recorded for {@code deploymentId}, removed or not. */
    Mono<Boolean> existsByDeploymentId(String deploymentId);

    /** Stamp {@code removed_at} on a rule that is still recorded as live. Returns the rows
     *  updated: 0 when it was already stamped (or never recorded), so a repeat is a no-op. */
    String MARK_REMOVED =
            "UPDATE service_deployment_route_rule SET removed_at = now() "
            + "WHERE rule_id = :ruleId AND removed_at IS NULL";

    @Modifying
    @Query(MARK_REMOVED)
    Mono<Long> markRemoved(@Param("ruleId") UUID ruleId);
}
