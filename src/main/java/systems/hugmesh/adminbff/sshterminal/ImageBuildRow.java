package systems.hugmesh.adminbff.sshterminal;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code image_build} (Liquibase changeset 171) — the durable shape for an
 * {@link ImageBuild}. PK is an app-generated {@code varchar(36)} UUID string; the entity
 * implements {@link Persistable} so a freshly-minted row INSERTs. {@link ImageBuild} stays
 * the domain record (constants); {@link ImageBuildRepository} maps between the two.
 */
@Table("image_build")
public record ImageBuildRow(
        @Id @Column("id") String id,
        @Column("created_at") Instant createdAt,
        @Column("requested_by") String requestedBy,
        @Column("target_user") String targetUser,
        @Column("domain") String domain,
        @Column("image_type") String imageType,
        @Column("hardware_class") String hardwareClass,
        @Column("device_id") String deviceId,
        @Column("status") String status,
        @Column("ssh_keys_allowed") boolean sshKeysAllowed,
        @Column("job_name") String jobName,
        @Column("image_ref") String imageRef,
        @Column("keys_ref") String keysRef,
        @Column("started_at") Instant startedAt,
        @Column("finished_at") Instant finishedAt,
        @Column("error") String error,
        @Column("image_spec_json") String imageSpecJson,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public ImageBuildRow(String id, Instant createdAt, String requestedBy, String targetUser,
                         String domain, String imageType, String hardwareClass, String deviceId,
                         String status, boolean sshKeysAllowed, String jobName, String imageRef,
                         String keysRef, Instant startedAt, Instant finishedAt, String error,
                         String imageSpecJson) {
        this(id, createdAt, requestedBy, targetUser, domain, imageType, hardwareClass, deviceId,
                status, sshKeysAllowed, jobName, imageRef, keysRef, startedAt, finishedAt, error,
                imageSpecJson, false);
    }

    ImageBuild toDomain() {
        return new ImageBuild(id, createdAt, requestedBy, targetUser, domain, imageType,
                hardwareClass, deviceId, status, sshKeysAllowed, jobName, imageRef, keysRef,
                startedAt, finishedAt, error, imageSpecJson);
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
