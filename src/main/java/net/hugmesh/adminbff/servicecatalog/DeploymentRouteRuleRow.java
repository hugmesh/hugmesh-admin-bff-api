package net.hugmesh.adminbff.servicecatalog;

import org.jspecify.annotations.Nullable;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * One row of {@code service_deployment_route_rule} (Liquibase changeset 400): the record that
 * the provision of {@link #deploymentId()} wrote the {@code gateway_route_access} row
 * {@link #ruleId()}. {@link #removedAt()} is {@code null} while the rule is still the
 * deployment's and is stamped when the rule was removed; the row itself is never deleted.
 *
 * <p>Read through derived finders only. Rows are written and stamped by the explicit
 * {@code @Query} statements on {@link DeploymentRouteRuleR2dbcRepository}, never through
 * {@code save()}.
 */
@Table("service_deployment_route_rule")
public record DeploymentRouteRuleRow(
        @Id @Column("rule_id") UUID ruleId,
        @Column("deployment_id") String deploymentId,
        @Column("recorded_at") Instant recordedAt,
        @Column("removed_at") @Nullable Instant removedAt) {
}
