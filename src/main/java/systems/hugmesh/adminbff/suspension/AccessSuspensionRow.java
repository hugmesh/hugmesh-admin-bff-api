package systems.hugmesh.adminbff.suspension;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code access_suspension} (Liquibase changeset 008 + the 010 {@code domain}
 * column) — the durable shape for an {@link AccessSuspension}. PK is a {@code varchar(36)}
 * app-generated UUID string; the entity implements {@link Persistable} so a freshly-minted
 * row INSERTs. {@link AccessSuspension} stays the domain record (constants + helpers);
 * {@link AccessSuspensionRepository} maps between the two.
 */
@Table("access_suspension")
public record AccessSuspensionRow(
        @Id @Column("id") String id,
        @Column("casdoor_user") String casdoorUser,
        @Column("localpart") String localpart,
        @Column("role") String role,
        @Column("state") String state,
        @Column("suspended_at") Instant suspendedAt,
        @Column("expires_at") Instant expiresAt,
        @Column("restore_role") boolean restoreRole,
        @Column("propagation_state") String propagationState,
        @Column("reason") String reason,
        @Column("set_by") String setBy,
        @Column("domain") String domain,
        @Transient boolean isNew) implements Persistable<String> {

    @org.springframework.data.annotation.PersistenceCreator
    public AccessSuspensionRow(String id, String casdoorUser, String localpart, String role, String state,
                               Instant suspendedAt, Instant expiresAt, boolean restoreRole,
                               String propagationState, String reason, String setBy, String domain) {
        this(id, casdoorUser, localpart, role, state, suspendedAt, expiresAt, restoreRole,
                propagationState, reason, setBy, domain, false);
    }

    AccessSuspension toDomain() {
        return new AccessSuspension(id, casdoorUser, localpart, role, state, suspendedAt, expiresAt,
                restoreRole, propagationState, reason, setBy, domain);
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
