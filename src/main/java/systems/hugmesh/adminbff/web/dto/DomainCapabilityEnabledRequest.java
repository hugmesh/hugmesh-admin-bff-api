package systems.hugmesh.adminbff.web.dto;

/**
 * Body for {@code PUT /bff/admin/domain-capabilities/{domain}/{capability}/enabled} — the
 * domain ADMIN's own key (own-domain only; SUPERADMIN may also set it for any domain,
 * INCLUDING the {@code ' global'} sentinel). Ships dark: a fresh gate defaults
 * {@code enabled=false}.
 */
public record DomainCapabilityEnabledRequest(boolean enabled) {
}
