package systems.hugmesh.adminbff.device;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code device_enrollment} (Liquibase changeset 130) — the durable shape for a
 * {@link DeviceEnrollment}. PK is a {@code varchar(36)} app-generated UUID string;
 * {@code machine_key_fp} is UNIQUE. Implements {@link Persistable} so a first report
 * INSERTs. {@link DeviceEnrollment} stays the domain record; {@link
 * DeviceEnrollmentRepository} maps between the two.
 */
@Table("device_enrollment")
public record DeviceEnrollmentRow(
        @Id @Column("id") String id,
        @Column("machine_key_fp") String machineKeyFp,
        @Column("hostname") String hostname,
        @Column("mesh_id") String meshId,
        @Column("tailnet_id") String tailnetId,
        @Column("first_reported_at") Instant firstReportedAt,
        @Column("last_reported_at") Instant lastReportedAt,
        @Column("report_count") long reportCount,
        @Transient boolean isNew) implements Persistable<String> {

    @org.springframework.data.annotation.PersistenceCreator
    public DeviceEnrollmentRow(String id, String machineKeyFp, String hostname, String meshId,
                               String tailnetId, Instant firstReportedAt, Instant lastReportedAt,
                               long reportCount) {
        this(id, machineKeyFp, hostname, meshId, tailnetId, firstReportedAt, lastReportedAt,
                reportCount, false);
    }

    DeviceEnrollment toDomain() {
        return new DeviceEnrollment(id, machineKeyFp, hostname, meshId, tailnetId,
                firstReportedAt, lastReportedAt, reportCount);
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
