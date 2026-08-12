package net.hugmesh.adminbff.egressvpn;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code vpn_node_assignment} (Liquibase changeset 080) — the durable shape for
 * a {@link VpnNodeAssignment} (config x NODE|DOMAIN). PK is a {@code varchar(36)}
 * app-generated UUID string; implements {@link Persistable} so a new assignment INSERTs.
 * {@link VpnNodeAssignment} stays the domain record; {@link VpnNodeAssignmentRepository}
 * maps between the two.
 */
@Table("vpn_node_assignment")
public record VpnNodeAssignmentRow(
        @Id @Column("id") String id,
        @Column("config_id") String configId,
        @Column("scope_type") String scopeType,
        @Column("target_node_id") String targetNodeId,
        @Column("target_domain") String targetDomain,
        @Column("service_slug") String serviceSlug,
        @Column("state") String state,
        @Column("assigned_by") String assignedBy,
        @Column("assigned_at") Instant assignedAt,
        @Column("revoked_at") Instant revokedAt,
        @Column("revoked_by") String revokedBy,
        @Column("domain") String domain,
        @Column("propagation_state") String propagationState,
        @Column("generation") long generation,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public VpnNodeAssignmentRow(String id, String configId, String scopeType, String targetNodeId,
                                String targetDomain, String serviceSlug, String state, String assignedBy,
                                Instant assignedAt, Instant revokedAt, String revokedBy, String domain,
                                String propagationState, long generation) {
        this(id, configId, scopeType, targetNodeId, targetDomain, serviceSlug, state, assignedBy,
                assignedAt, revokedAt, revokedBy, domain, propagationState, generation, false);
    }

    VpnNodeAssignment toDomain() {
        return new VpnNodeAssignment(id, configId, scopeType, targetNodeId, targetDomain, serviceSlug,
                state, assignedBy, assignedAt, revokedAt, revokedBy, domain, propagationState, generation);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
