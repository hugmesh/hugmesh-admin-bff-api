package net.hugmesh.adminbff.device;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code device_ssh_license} (Liquibase changeset 011) — the durable shape for
 * an {@link SshLicense} grant. PK is a {@code varchar(36)} app-generated UUID string;
 * implements {@link Persistable} so a new grant INSERTs. {@link SshLicense} stays the
 * domain record; {@link SshLicenseRepository} maps between the two.
 */
@Table("device_ssh_license")
public record SshLicenseRow(
        @Id @Column("id") String id,
        @Column("operator") String operator,
        @Column("scope_type") String scopeType,
        @Column("device_id") String deviceId,
        @Column("target_domain") String targetDomain,
        @Column("key_fingerprints") String keyFingerprints,
        @Column("state") String state,
        @Column("granted_by") String grantedBy,
        @Column("granted_at") Instant grantedAt,
        @Column("revoked_at") Instant revokedAt,
        @Column("revoked_by") String revokedBy,
        @Column("domain") String domain,
        @Column("propagation_state") String propagationState,
        @Column("generation") long generation,
        @Transient boolean isNew) implements Persistable<String> {

    @org.springframework.data.annotation.PersistenceCreator
    public SshLicenseRow(String id, String operator, String scopeType, String deviceId,
                         String targetDomain, String keyFingerprints, String state, String grantedBy,
                         Instant grantedAt, Instant revokedAt, String revokedBy, String domain,
                         String propagationState, long generation) {
        this(id, operator, scopeType, deviceId, targetDomain, keyFingerprints, state, grantedBy,
                grantedAt, revokedAt, revokedBy, domain, propagationState, generation, false);
    }

    SshLicense toDomain() {
        return new SshLicense(id, operator, scopeType, deviceId, targetDomain, keyFingerprints,
                state, grantedBy, grantedAt, revokedAt, revokedBy, domain, propagationState, generation);
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
