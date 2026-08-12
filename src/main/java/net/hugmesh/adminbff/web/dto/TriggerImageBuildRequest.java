package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/admin/image-builds} — an ADMIN/SUPERADMIN trigger to build an image
 * for a target user. The {@code @NotBlank}/{@code @Pattern} guards make a malformed request a
 * clean 400 BEFORE any write.
 *
 * <p>SECURITY: this body carries ONLY the request intent. The {@code requestedBy} (JWT subject)
 * and the {@code domain} (derived from the VALIDATED issuer — NEVER a client field) are stamped
 * server-side; the own-domain wall and target-user residency are enforced in the service. There
 * is intentionally NO domain field here: a client cannot pick a tenant.
 *
 * <ul>
 *   <li>{@code targetUser} — the subject the image is FOR (must resolve to a user in the
 *       caller's own domain unless the caller is SUPERADMIN).</li>
 *   <li>{@code imageType} — {@code primary} / {@code mesh-extension} / {@code client} (the
 *       closed, CHECK-constrained vocabulary).</li>
 *   <li>{@code hardwareClass} — optional target hardware (e.g. {@code rpi5}, {@code x86-64}).</li>
 *   <li>{@code sshKeysAllowed} — whether the build may emit a downloadable (non-secret) SSH-keys
 *       bundle. Absent/null defaults to {@code false} (fail-closed) in the service.</li>
 * </ul>
 */
public record TriggerImageBuildRequest(

        @NotBlank(message = "targetUser is required")
        @Size(max = 400, message = "targetUser is too long")
        // Allowlist charset: this value is substituted into a quoted YAML scalar in the
        // image-gen Job manifest (ImageBuildOrchestrator.renderManifest). Reject quotes,
        // newlines and other control characters that could break out of the scalar and
        // inject sibling Job keys — see the YAML-injection finding. Subject/identifier
        // charset (alnum + . _ @ / -) covers every legitimate target-user form.
        @Pattern(regexp = "^[A-Za-z0-9._@/-]{1,400}$",
                message = "targetUser contains invalid characters")
        String targetUser,

        @NotBlank(message = "imageType is required")
        @Pattern(regexp = "primary|mesh-extension|client",
                message = "imageType must be primary, mesh-extension or client")
        String imageType,

        @Size(max = 64, message = "hardwareClass is too long")
        // Allowlist charset: also substituted into a quoted YAML scalar — same YAML-injection
        // hardening as targetUser. Hardware classes are short tokens (e.g. rpi5, x86-64).
        @Pattern(regexp = "^[A-Za-z0-9._-]{1,64}$",
                message = "hardwareClass contains invalid characters")
        @Nullable
        String hardwareClass,

        @Nullable
        Boolean sshKeysAllowed) {

    /** Fail-closed default: keys are NOT allowed unless explicitly requested true. */
    public boolean sshKeysAllowedOrFalse() {
        return Boolean.TRUE.equals(sshKeysAllowed);
    }
}
