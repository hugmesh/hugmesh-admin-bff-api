package net.hugmesh.adminbff.radio;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code node_radio_device} (Liquibase changeset 300) — the durable shape for a
 * {@link RadioDevice}. PK is a {@code varchar(36)} UUID string (DB-generated, changelog-200
 * idiom); the entity implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link RadioDeviceRepository} maps between the two.
 */
@Table("node_radio_device")
public record RadioDeviceRow(
        @Id @Column("id") String id,
        @Column("device_id") String deviceId,
        @Column("transport") String transport,
        @Column("serial_path") String serialPath,
        @Column("host") String host,
        @Column("port") Integer port,
        @Column("topic_root") String topicRoot,
        @Column("channel_name") String channelName,
        @Column("gateway_node_id") String gatewayNodeId,
        @Column("radio_id") String radioId,
        @Column("mesh_channel") int meshChannel,
        @Column("state") String state,
        @Column("domain") String domain,
        @Column("propagation_state") String propagationState,
        @Column("generation") long generation,
        @Column("created_by") String createdBy,
        @Column("created_at") Instant createdAt,
        @Column("detached_at") Instant detachedAt,
        @Column("detached_by") String detachedBy,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public RadioDeviceRow(String id, String deviceId, String transport, String serialPath,
                          String host, Integer port, String topicRoot, String channelName,
                          String gatewayNodeId, String radioId, int meshChannel, String state,
                          String domain, String propagationState, long generation,
                          String createdBy, Instant createdAt, Instant detachedAt,
                          String detachedBy) {
        this(id, deviceId, transport, serialPath, host, port, topicRoot, channelName,
                gatewayNodeId, radioId, meshChannel, state, domain, propagationState, generation,
                createdBy, createdAt, detachedAt, detachedBy, false);
    }

    RadioDevice toDomain() {
        return new RadioDevice(id, deviceId, transport, serialPath, host, port, topicRoot,
                channelName, gatewayNodeId, radioId, meshChannel, state, domain,
                propagationState, generation, createdBy, createdAt, detachedAt, detachedBy);
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
