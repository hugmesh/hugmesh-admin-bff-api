package net.hugmesh.adminbff.desktop;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code desktop_install_request} (Liquibase changeset 140) — the durable shape for
 * a {@link DesktopInstallRequest}. PK is an app-generated {@code varchar(36)} UUID string; the
 * entity implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link DesktopInstallRequestRepository} maps between the two.
 */
@Table("desktop_install_request")
public record DesktopInstallRequestRow(
        @Id @Column("id") String id,
        @Column("requester") String requester,
        @Column("app_ref") String appRef,
        @Column("device_id") String deviceId,
        @Column("status") String status,
        @Column("decided_by") String decidedBy,
        @Column("decided_at") Instant decidedAt,
        @Column("domain") String domain,
        @Column("created_at") Instant createdAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public DesktopInstallRequestRow(String id, String requester, String appRef, String deviceId,
                                    String status, String decidedBy, Instant decidedAt,
                                    String domain, Instant createdAt) {
        this(id, requester, appRef, deviceId, status, decidedBy, decidedAt, domain, createdAt, false);
    }

    DesktopInstallRequest toDomain() {
        return new DesktopInstallRequest(id, requester, appRef, deviceId, status, decidedBy,
                decidedAt, domain, createdAt);
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
