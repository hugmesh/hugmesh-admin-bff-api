package net.hugmesh.adminbff.desktop;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code desktop_sudo_grant} (Liquibase changeset 140) — the durable shape for a
 * {@link DesktopSudoGrant}. PK is an app-generated {@code varchar(36)} UUID string; the entity
 * implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link DesktopSudoGrantRepository} maps between the two.
 */
@Table("desktop_sudo_grant")
public record DesktopSudoGrantRow(
        @Id @Column("id") String id,
        @Column("subject") String subject,
        @Column("device_id") String deviceId,
        @Column("state") String state,
        @Column("granted_by") String grantedBy,
        @Column("granted_at") Instant grantedAt,
        @Column("revoked_at") Instant revokedAt,
        @Column("revoked_by") String revokedBy,
        @Column("domain") String domain,
        @Column("propagation_state") String propagationState,
        @Column("generation") long generation,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public DesktopSudoGrantRow(String id, String subject, String deviceId, String state,
                               String grantedBy, Instant grantedAt, Instant revokedAt,
                               String revokedBy, String domain, String propagationState,
                               long generation) {
        this(id, subject, deviceId, state, grantedBy, grantedAt, revokedAt, revokedBy, domain,
                propagationState, generation, false);
    }

    DesktopSudoGrant toDomain() {
        return new DesktopSudoGrant(id, subject, deviceId, state, grantedBy, grantedAt, revokedAt,
                revokedBy, domain, propagationState, generation);
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
