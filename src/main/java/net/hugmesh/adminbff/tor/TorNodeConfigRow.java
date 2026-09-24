package net.hugmesh.adminbff.tor;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code tor_node_config} (Liquibase changeset 360) — the durable shape of a
 * {@link TorNodeConfig}. Written only through {@link TorNodeConfigRowRepository#upsertUpstream}.
 */
@Table("tor_node_config")
public record TorNodeConfigRow(
        @Id @Column("id") String id,
        @Column("machine_key_fp") String machineKeyFp,
        @Column("upstream_managed") boolean upstreamManaged,
        @Column("upstream") String upstream,
        @Column("config_generation") long configGeneration,
        @Column("updated_by") String updatedBy,
        @Column("updated_at") Instant updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public TorNodeConfigRow(String id, String machineKeyFp, boolean upstreamManaged, String upstream,
                            long configGeneration, String updatedBy, Instant updatedAt) {
        this(id, machineKeyFp, upstreamManaged, upstream, configGeneration, updatedBy, updatedAt, false);
    }

    TorNodeConfig toDomain() {
        return new TorNodeConfig(machineKeyFp, upstreamManaged, upstream, configGeneration,
                updatedBy, updatedAt);
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
