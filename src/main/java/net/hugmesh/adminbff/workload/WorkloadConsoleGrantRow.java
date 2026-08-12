package net.hugmesh.adminbff.workload;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code workload_console_grant} (Liquibase changeset 110) — the durable shape for a
 * {@link WorkloadConsoleGrant}. PK is an app-generated {@code varchar(36)} UUID string; the
 * entity implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link WorkloadConsoleGrantRepository} maps between the two.
 */
@Table("workload_console_grant")
public record WorkloadConsoleGrantRow(
        @Id @Column("id") String id,
        @Column("grantee") String grantee,
        @Column("target_domain") String targetDomain,
        @Column("access_level") String accessLevel,
        @Column("log_access") boolean logAccess,
        @Column("state") String state,
        @Column("granted_by") String grantedBy,
        @Column("granted_at") Instant grantedAt,
        @Column("expires_at") Instant expiresAt,
        @Column("revoked_at") Instant revokedAt,
        @Column("revoked_by") String revokedBy,
        @Column("domain") String domain,
        @Column("propagation_state") String propagationState,
        @Column("generation") long generation,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public WorkloadConsoleGrantRow(String id, String grantee, String targetDomain,
                                   String accessLevel, boolean logAccess, String state,
                                   String grantedBy, Instant grantedAt, Instant expiresAt,
                                   Instant revokedAt, String revokedBy, String domain,
                                   String propagationState, long generation) {
        this(id, grantee, targetDomain, accessLevel, logAccess, state, grantedBy, grantedAt,
                expiresAt, revokedAt, revokedBy, domain, propagationState, generation, false);
    }

    WorkloadConsoleGrant toDomain() {
        return new WorkloadConsoleGrant(id, grantee, targetDomain, accessLevel, logAccess, state,
                grantedBy, grantedAt, expiresAt, revokedAt, revokedBy, domain, propagationState,
                generation);
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
