package net.hugmesh.adminbff.oidcprovider;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.OffsetDateTime;

/**
 * One {@code (domain, provider, role_name)} row in {@code oidc_provider_default_roles}
 * (Liquibase changeset 081). When a new user registers via the given OIDC provider, the
 * role_name is assigned to their Casdoor account by the registration flow.
 *
 * <p>Spring Data R2DBC entity. The PK is COMPOSITE ({@code domain, provider, role_name});
 * R2DBC has no composite-id support, so reads use derived finders, deletes a derived
 * {@code deleteBy...}, and the idempotent insert is an {@code @Query} (ON CONFLICT DO
 * NOTHING). The {@code @Id} on {@code roleName} satisfies the repository's ID type only —
 * {@code save}/{@code findById} are never used on this entity.
 */
@Table("oidc_provider_default_roles")
public record OidcProviderRole(
        @Column("domain") String domain,
        @Column("provider") String provider,
        @Id @Column("role_name") String roleName,
        @Column("created_at") OffsetDateTime createdAt) {
}
