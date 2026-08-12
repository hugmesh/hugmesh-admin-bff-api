package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/superadmin/phone-devices/{deviceId}/lock} (SUPERADMIN + step-up) —
 * the operator's reason for locking the device, stamped onto {@code phone_device.lock_reason}.
 * {@code reason} is a single word (no {@code @JsonProperty}) and OPTIONAL: a null/absent reason
 * locks with a NULL reason (the lock itself, the actor, and the audit generation are the
 * record). Bounded to the {@code lock_reason} column width (512).
 */
public record PhoneLockRequest(
        @Size(max = 512, message = "reason is too long")
        @Nullable String reason) {
}
