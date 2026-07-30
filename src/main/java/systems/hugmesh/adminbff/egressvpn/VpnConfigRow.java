package systems.hugmesh.adminbff.egressvpn;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code vpn_config} (Liquibase changeset 080) — the durable shape for a
 * {@link VpnConfig}. PK is a {@code varchar(36)} app-generated UUID string; implements
 * {@link Persistable} so a new config INSERTs. The row holds ONLY a {@code secret_ref} +
 * metadata — never the {@code .conf} bytes. {@link VpnConfig} stays the domain record;
 * {@link VpnConfigRepository} maps between the two.
 */
@Table("vpn_config")
public record VpnConfigRow(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("name") String name,
        @Column("kind") String kind,
        @Column("provider") String provider,
        @Column("endpoint") String endpoint,
        @Column("secret_ref") String secretRef,
        @Column("state") String state,
        @Column("created_by") String createdBy,
        @Column("created_at") Instant createdAt,
        @Column("revoked_at") Instant revokedAt,
        @Column("revoked_by") String revokedBy,
        @Column("propagation_state") String propagationState,
        @Column("generation") long generation,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public VpnConfigRow(String id, String domain, String name, String kind, String provider,
                        String endpoint, String secretRef, String state, String createdBy,
                        Instant createdAt, Instant revokedAt, String revokedBy, String propagationState,
                        long generation) {
        this(id, domain, name, kind, provider, endpoint, secretRef, state, createdBy, createdAt,
                revokedAt, revokedBy, propagationState, generation, false);
    }

    VpnConfig toDomain() {
        return new VpnConfig(id, domain, name, kind, provider, endpoint, secretRef, state, createdBy,
                createdAt, revokedAt, revokedBy, propagationState, generation);
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
