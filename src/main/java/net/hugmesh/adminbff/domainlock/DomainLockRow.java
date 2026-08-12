package net.hugmesh.adminbff.domainlock;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code domain_lock} (Liquibase changeset 009 + the 010 {@code domain}
 * column) — the durable shape for a {@link DomainLock}. PK is a {@code varchar(36)}
 * app-generated UUID string; the entity implements {@link Persistable} so a freshly-minted
 * row INSERTs. {@link DomainLock} stays the domain record; {@link DomainLockRepository}
 * maps between the two.
 */
@Table("domain_lock")
public record DomainLockRow(
        @Id @Column("id") String id,
        @Column("casdoor_user") String casdoorUser,
        @Column("localpart") String localpart,
        @Column("role") String role,
        @Column("state") String state,
        @Column("created_at") Instant createdAt,
        @Column("propagation_state") String propagationState,
        @Column("reason") String reason,
        @Column("set_by") String setBy,
        @Column("domain") String domain,
        @Transient boolean isNew) implements Persistable<String> {

    @org.springframework.data.annotation.PersistenceCreator
    public DomainLockRow(String id, String casdoorUser, String localpart, String role, String state,
                         Instant createdAt, String propagationState, String reason, String setBy,
                         String domain) {
        this(id, casdoorUser, localpart, role, state, createdAt, propagationState, reason, setBy,
                domain, false);
    }

    DomainLock toDomain() {
        return new DomainLock(id, casdoorUser, localpart, role, state, createdAt,
                propagationState, reason, setBy, domain);
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
