package net.hugmesh.adminbff.web.dto;

/**
 * Body for {@code PUT /bff/admin/domain-capabilities/{domain}/{capability}} (SUPERADMIN
 * only). Flips the {@code granted} key — on a normal domain this is the per-domain grant;
 * on the {@code ' global'} sentinel domain this SAME field IS the platform-wide kill
 * switch. Ships dark: a fresh gate defaults {@code granted=false}.
 */
public record DomainCapabilityGrantedRequest(boolean granted) {
}
