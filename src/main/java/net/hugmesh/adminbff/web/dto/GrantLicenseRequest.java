package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Body for the two grant endpoints (SUPERADMIN):
 * {@code POST /bff/admin/device-licenses/{deviceId}/grant} (DEVICE scope, deviceId from
 * the path) and {@code POST /bff/admin/device-licenses/domains/{domain}/grant} (DOMAIN
 * scope, domain from the path). The license target (device or domain) is the PATH
 * variable; this body carries the operator + the pinned key fingerprints [FIX-PINKEY].
 *
 * <ul>
 *   <li>{@code operator} — the Casdoor subject being licensed to SSH.</li>
 *   <li>{@code keyFingerprints} — REQUIRED, non-empty: the EXACT SSH pubkey
 *       fingerprint(s) the operator may present (FIX-PINKEY). A grant with no pinned key
 *       would compile to nothing (fail-closed), so an empty list is a 400 here rather
 *       than a silently-useless license.</li>
 * </ul>
 */
public record GrantLicenseRequest(
        @NotBlank(message = "operator is required")
        @Size(max = 400, message = "operator is too long")
        String operator,

        @NotEmpty(message = "keyFingerprints is required (pin at least one SSH pubkey fingerprint)")
        @Size(max = 32, message = "too many key fingerprints")
        List<@NotBlank(message = "a key fingerprint must not be blank")
              @Size(max = 256, message = "a key fingerprint is too long") String> keyFingerprints) {
}
