package net.hugmesh.adminbff.phone;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code fleet_entitlement} (Liquibase changeset 306) — the durable shape for a
 * {@link FleetEntitlement}. The PK is the natural {@code subject} varchar (NOT a DB-generated
 * uuid), so there is no {@code Persistable}/{@code isNew} plumbing and {@code save()} is never
 * called: {@link FleetEntitlementRowRepository} writes via hand-written UPDATE-then-INSERT
 * upsert queries and reads via the derived list finder.
 */
@Table("fleet_entitlement")
public record FleetEntitlementRow(
        @Id @Column("subject") String subject,
        @Column("active") boolean active,
        @Column("seats") Integer seats,
        @Column("expires_at") Instant expiresAt,
        @Column("updated_at") Instant updatedAt) {

    FleetEntitlement toDomain() {
        return new FleetEntitlement(subject, active, seats, expiresAt, updatedAt);
    }
}
