package net.hugmesh.adminbff.workload;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code workload_console_config} (Liquibase changeset 110) — the durable shape for
 * a {@link WorkloadConsoleConfig}. PK is an app-generated {@code varchar(36)} UUID string; the
 * entity implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link WorkloadConsoleConfigRepository} maps between the two.
 */
@Table("workload_console_config")
public record WorkloadConsoleConfigRow(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("admin_enabled") boolean adminEnabled,
        @Column("dangerous_tier_enabled") boolean dangerousTierEnabled,
        @Column("updated_by") String updatedBy,
        @Column("updated_at") Instant updatedAt,
        @Column("generation") long generation,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public WorkloadConsoleConfigRow(String id, String domain, boolean adminEnabled,
                                    boolean dangerousTierEnabled, String updatedBy, Instant updatedAt,
                                    long generation) {
        this(id, domain, adminEnabled, dangerousTierEnabled, updatedBy, updatedAt, generation, false);
    }

    WorkloadConsoleConfig toDomain() {
        return new WorkloadConsoleConfig(id, domain, adminEnabled, dangerousTierEnabled, updatedBy,
                updatedAt, generation);
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
