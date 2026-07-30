package systems.hugmesh.adminbff.storage;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code storage_service_assignment} (Liquibase changeset 085) — the durable shape
 * for a {@link ServiceAssignment}. PK is an app-generated {@code varchar(36)} UUID string; the
 * entity implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link ServiceAssignmentRepository} maps between the two.
 */
@Table("storage_service_assignment")
public record ServiceAssignmentRow(
        @Id @Column("id") String id,
        @Column("pool_id") String poolId,
        @Column("service_name") String serviceName,
        @Column("pvc_name") String pvcName,
        @Column("requested_bytes") long requestedBytes,
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
    public ServiceAssignmentRow(String id, String poolId, String serviceName, String pvcName,
                                long requestedBytes, String state, String assignedBy,
                                Instant assignedAt, Instant revokedAt, String revokedBy,
                                String domain, String propagationState, long generation) {
        this(id, poolId, serviceName, pvcName, requestedBytes, state, assignedBy, assignedAt,
                revokedAt, revokedBy, domain, propagationState, generation, false);
    }

    ServiceAssignment toDomain() {
        return new ServiceAssignment(id, poolId, serviceName, pvcName, requestedBytes, state,
                assignedBy, assignedAt, revokedAt, revokedBy, domain, propagationState, generation);
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
