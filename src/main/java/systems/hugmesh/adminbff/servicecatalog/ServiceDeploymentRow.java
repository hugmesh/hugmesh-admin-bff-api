package systems.hugmesh.adminbff.servicecatalog;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code service_deployment} (Liquibase changeset 102) — the durable shape for a
 * {@link ServiceDeployment}. PK is an app-generated {@code varchar(36)} UUID string; the entity
 * implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link ServiceDeploymentRepository} maps between the two.
 */
@Table("service_deployment")
public record ServiceDeploymentRow(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("service_key") String serviceKey,
        @Column("profile_ref") String profileRef,
        @Column("state") String state,
        @Column("created_at") Instant createdAt,
        @Column("ending_at") Instant endingAt,
        @Column("enforce_actions") String enforceActions,
        @Column("propagation_state") String propagationState,
        @Column("ended_at") Instant endedAt,
        @Column("created_by_subject") String createdBySubject,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public ServiceDeploymentRow(String id, String domain, String serviceKey, String profileRef,
                                String state, Instant createdAt, Instant endingAt,
                                String enforceActions, String propagationState, Instant endedAt,
                                String createdBySubject) {
        this(id, domain, serviceKey, profileRef, state, createdAt, endingAt, enforceActions,
                propagationState, endedAt, createdBySubject, false);
    }

    ServiceDeployment toDomain() {
        return new ServiceDeployment(id, domain, serviceKey, profileRef, state, createdAt, endingAt,
                enforceActions, propagationState, endedAt, createdBySubject);
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
