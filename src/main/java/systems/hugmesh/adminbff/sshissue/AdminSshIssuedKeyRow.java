package systems.hugmesh.adminbff.sshissue;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code admin_ssh_issued_key} (Liquibase changeset 172) — the issuance AUDIT
 * record for admin SSH key-ISSUANCE. PK is a {@code varchar(36)} app-generated UUID string;
 * implements {@link Persistable} so a new issuance INSERTs. NO private-key column exists.
 * {@link AdminSshIssuedKey} stays the domain record; {@link AdminSshIssuedKeyRepository}
 * maps between the two.
 */
@Table("admin_ssh_issued_key")
public record AdminSshIssuedKeyRow(
        @Id @Column("id") String id,
        @Column("device_id") String deviceId,
        @Column("license_id") String licenseId,
        @Column("operator") String operator,
        @Column("key_type") String keyType,
        @Column("public_key") String publicKey,
        @Column("fingerprint") String fingerprint,
        @Column("issued_by") String issuedBy,
        @Column("issued_at") Instant issuedAt,
        @Column("downloaded_at") Instant downloadedAt,
        @Column("state") String state,
        @Column("domain") String domain,
        @Column("revoked_at") Instant revokedAt,
        @Column("revoked_by") String revokedBy,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public AdminSshIssuedKeyRow(String id, String deviceId, String licenseId, String operator,
                               String keyType, String publicKey, String fingerprint, String issuedBy,
                               Instant issuedAt, Instant downloadedAt, String state, String domain,
                               Instant revokedAt, String revokedBy) {
        this(id, deviceId, licenseId, operator, keyType, publicKey, fingerprint, issuedBy, issuedAt,
                downloadedAt, state, domain, revokedAt, revokedBy, false);
    }

    AdminSshIssuedKey toDomain() {
        return new AdminSshIssuedKey(id, deviceId, licenseId, operator, keyType, publicKey, fingerprint,
                issuedBy, issuedAt, downloadedAt, state, domain, revokedAt, revokedBy);
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
