package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Min;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * Body for {@code PUT /bff/superadmin/fleet-entitlements/{subject}} (SUPERADMIN + step-up) —
 * upsert the per-subject FLEET-ADMIN subscription (changeset 306). All three fields are
 * OPTIONAL: {@code active} defaults to {@code true} when absent (a bare {@code {}} upsert grants
 * access, mirroring the column default), {@code seats} is an advisory count (NOT enforced by the
 * tenancy wall), and {@code expiresAt} is an optional ISO-8601 expiry the entitlement check
 * evaluates fail-closed. Camel-case wire (this repo configures no global naming strategy).
 */
public record FleetEntitlementRequest(
        @Nullable Boolean active,

        @Min(value = 0, message = "seats must not be negative")
        @Nullable Integer seats,

        @Nullable Instant expiresAt) {

    /** The effective active flag — defaults to {@code true} when the field is absent. */
    public boolean activeOrDefault() {
        return active == null || active;
    }
}
