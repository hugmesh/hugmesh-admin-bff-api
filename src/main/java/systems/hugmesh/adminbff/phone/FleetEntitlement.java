package systems.hugmesh.adminbff.phone;

import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * One {@code fleet_entitlement} row (Liquibase changeset 306) — the per-subject FLEET-ADMIN
 * SUBSCRIPTION record. A non-superadmin {@code FLEET_ADMIN} may reach the public
 * {@code /bff/admin/phone-fleet/**} owner surface ONLY while an ACTIVE, unexpired entitlement
 * exists for their Casdoor subject (SUPERADMIN is exempt).
 *
 * <p>Keyed on {@code subject} (the natural PRIMARY KEY). {@code active} is the on/off switch,
 * {@code seats} an optional advisory count (NOT enforced by the tenancy wall), {@code expiresAt}
 * an optional expiry the {@link FleetEntitlementService#isEntitled(String)} check evaluates
 * fail-closed against the DB clock. Superadmin-managed via
 * {@code /bff/superadmin/fleet-entitlements}.
 */
public record FleetEntitlement(
        String subject,
        boolean active,
        @Nullable Integer seats,
        @Nullable Instant expiresAt,
        Instant updatedAt) {
}
