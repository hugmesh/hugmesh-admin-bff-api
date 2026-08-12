package net.hugmesh.adminbff.workload;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code workload_console_intent} (Liquibase changeset 110) — the durable shape for
 * a {@link WorkloadConsoleIntent}. PK is an app-generated {@code varchar(36)} UUID string; the
 * entity implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link WorkloadConsoleIntentRepository} maps between the two.
 */
@Table("workload_console_intent")
public record WorkloadConsoleIntentRow(
        @Id @Column("id") String id,
        @Column("kind") String kind,
        @Column("namespace") String namespace,
        @Column("workload") String workload,
        @Column("image_ref") String imageRef,
        @Column("replicas") Integer replicas,
        @Column("requested_by") String requestedBy,
        @Column("requested_at") Instant requestedAt,
        @Column("domain") String domain,
        @Column("propagation_state") String propagationState,
        @Column("generation") long generation,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public WorkloadConsoleIntentRow(String id, String kind, String namespace, String workload,
                                    String imageRef, Integer replicas, String requestedBy,
                                    Instant requestedAt, String domain, String propagationState,
                                    long generation) {
        this(id, kind, namespace, workload, imageRef, replicas, requestedBy, requestedAt, domain,
                propagationState, generation, false);
    }

    WorkloadConsoleIntent toDomain() {
        return new WorkloadConsoleIntent(id, kind, namespace, workload, imageRef, replicas,
                requestedBy, requestedAt, domain, propagationState, generation);
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
