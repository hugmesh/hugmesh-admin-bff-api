package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code PUT /bff/superadmin/phone-devices/{deviceId}/owner} (SUPERADMIN + step-up) —
 * assign the OPERATOR-AUTHORITATIVE fleet owner (changeset 305) to a phone. Both fields are
 * REQUIRED: {@code physicalOwner} is the Casdoor subject the device belongs to and
 * {@code ownerDomain} is the brand/domain — together they are the SOLE tenancy wall the public
 * {@code /bff/admin/phone-fleet/**} FLEET_ADMIN surface predicates on. Camel-case wire (this
 * repo configures no global naming strategy). Bounded to the column widths (400 / 253).
 */
public record PhoneOwnerRequest(
        @NotBlank(message = "physicalOwner is required")
        @Size(max = 400, message = "physicalOwner is too long")
        String physicalOwner,

        @NotBlank(message = "ownerDomain is required")
        @Size(max = 253, message = "ownerDomain is too long")
        String ownerDomain) {
}
