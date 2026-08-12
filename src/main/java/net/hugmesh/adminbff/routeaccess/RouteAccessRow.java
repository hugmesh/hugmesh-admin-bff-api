package net.hugmesh.adminbff.routeaccess;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * One row of {@code gateway_route_access} (Liquibase changeset 001 + the 010 {@code
 * domain} column) — the durable shape for a {@link RouteRule}. PK is a {@code uuid};
 * {@link RouteRule} stays the JSON projection (string id, {@code @JsonProperty} names),
 * and {@link RouteAccessRepository} maps between the two. Implements {@link Persistable}
 * so an assigned-UUID new row INSERTs.
 *
 * <p>The {@code mfa_required} column (Liquibase band 181, the dual-write trio closing leg)
 * IS mapped here — {@code @Column("mfa_required") boolean mfaRequired}, matching the gateway
 * {@code GatewayRouteAccessRow} (its {@code mfaRequired} sits between {@code domain} and
 * {@code updated_at}) + the generator {@code 20-schema.sql} (`mfa_required boolean NOT NULL
 * DEFAULT false`). DEFAULT false everywhere: admin-bff reads/writes the column through but
 * does NOT enforce MFA (the gateway's {@code GatewayRouteAccessFilter.decide()} is the sole
 * enforcer) — this is schema/representation consistency only.
 */
@Table("gateway_route_access")
public record RouteAccessRow(
        @Id @Column("id") UUID id,
        @Column("gateway") String gateway,
        @Column("url_pattern") String urlPattern,
        @Column("role") String role,
        @Column("casdoor_user") String casdoorUser,
        @Column("allow") boolean allow,
        @Column("domain") String domain,
        @Column("mfa_required") boolean mfaRequired,
        @Column("updated_at") LocalDateTime updatedAt,
        @Transient boolean isNew) implements Persistable<UUID> {

    @org.springframework.data.annotation.PersistenceCreator
    public RouteAccessRow(UUID id, String gateway, String urlPattern, String role, String casdoorUser,
                          boolean allow, String domain, boolean mfaRequired, LocalDateTime updatedAt) {
        this(id, gateway, urlPattern, role, casdoorUser, allow, domain, mfaRequired, updatedAt, false);
    }

    RouteRule toRule() {
        return new RouteRule(id.toString(), gateway, urlPattern, role, casdoorUser, allow, domain, mfaRequired);
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
