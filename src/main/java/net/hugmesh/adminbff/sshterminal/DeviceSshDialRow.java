package net.hugmesh.adminbff.sshterminal;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code device_ssh_dial} (Liquibase changeset 170) — the durable shape for a
 * {@link DeviceSshDial}. PK is an app-generated {@code varchar(36)} UUID string; the entity
 * implements {@link Persistable} so a freshly-minted row INSERTs. {@link DeviceSshDial} stays
 * the domain record; {@link DeviceSshDialRepository} maps between the two.
 */
@Table("device_ssh_dial")
public record DeviceSshDialRow(
        @Id @Column("id") String id,
        @Column("device_id") String deviceId,
        @Column("dial_user") String dialUser,
        @Column("host_key_pub") String hostKeyPub,
        @Column("host_key_fp") String hostKeyFp,
        @Column("dial_pub_fp") String dialPubFp,
        @Column("vault_ref") String vaultRef,
        @Column("k8s_secret_name") String k8sSecretName,
        @Column("seeded_by_build_id") String seededByBuildId,
        @Column("status") String status,
        @Column("generation") long generation,
        @Column("created_at") Instant createdAt,
        @Column("rotated_at") Instant rotatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public DeviceSshDialRow(String id, String deviceId, String dialUser, String hostKeyPub,
                            String hostKeyFp, String dialPubFp, String vaultRef, String k8sSecretName,
                            String seededByBuildId, String status, long generation,
                            Instant createdAt, Instant rotatedAt) {
        this(id, deviceId, dialUser, hostKeyPub, hostKeyFp, dialPubFp, vaultRef, k8sSecretName,
                seededByBuildId, status, generation, createdAt, rotatedAt, false);
    }

    DeviceSshDial toDomain() {
        return new DeviceSshDial(id, deviceId, dialUser, hostKeyPub, hostKeyFp, dialPubFp,
                vaultRef, k8sSecretName, seededByBuildId, status, generation, createdAt, rotatedAt);
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
