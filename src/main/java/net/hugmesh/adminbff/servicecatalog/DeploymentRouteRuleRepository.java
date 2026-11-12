package net.hugmesh.adminbff.servicecatalog;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Reactive (R2DBC) store for {@code service_deployment_route_rule} — the record of WHICH
 * {@code gateway_route_access} rows each deployment's provision wrote (schema in Liquibase
 * {@code db/changelog/400-service-deployment-route-rule.xml}).
 *
 * <p>{@link AddServiceEffector} is the only caller. Provision {@link #record}s every rule it
 * writes, in the same transaction as the rule itself; teardown reads {@link #liveRuleIds}, removes
 * exactly those rules and {@link #markRemoved stamps} each record. A record is never deleted: a
 * deployment that {@link #hasEverRecorded has ever recorded} a rule is known to this table for
 * good, which is what separates "already torn down" from "provisioned before rules were
 * recorded".
 *
 * <p>Rule ids travel as the {@code String} form {@link net.hugmesh.adminbff.routeaccess.RouteRule}
 * carries. The table has no per-row tenant column of its own: the brand check is made where the
 * rule is deleted, which is scoped to the deployment's domain.
 */
@Repository
public class DeploymentRouteRuleRepository {

    private final DeploymentRouteRuleR2dbcRepository repo;

    public DeploymentRouteRuleRepository(DeploymentRouteRuleR2dbcRepository repo) {
        this.repo = repo;
    }

    /** Record that {@code deploymentId}'s provision wrote the rule {@code ruleId}. */
    public Mono<Void> record(String deploymentId, String ruleId) {
        return repo.insert(UUID.fromString(ruleId), deploymentId).then();
    }

    /** The ids of the rules still recorded as {@code deploymentId}'s, in no particular order.
     *  Empty for a deployment that never recorded one, or whose rules have all been removed. */
    public Flux<String> liveRuleIds(String deploymentId) {
        return repo.findByDeploymentIdAndRemovedAtIsNull(deploymentId)
                .map(row -> row.ruleId().toString());
    }

    /** True once any rule was EVER recorded for {@code deploymentId}, removed or not. */
    public Mono<Boolean> hasEverRecorded(String deploymentId) {
        return repo.existsByDeploymentId(deploymentId);
    }

    /** True when {@code ruleId} was written by a recorded provision of ANY deployment. */
    public Mono<Boolean> isRecorded(String ruleId) {
        return repo.existsById(UUID.fromString(ruleId));
    }

    /** Stamp the record of {@code ruleId} as removed. A repeat, or an id that was never
     *  recorded, changes nothing. */
    public Mono<Void> markRemoved(String ruleId) {
        return repo.markRemoved(UUID.fromString(ruleId)).then();
    }
}
