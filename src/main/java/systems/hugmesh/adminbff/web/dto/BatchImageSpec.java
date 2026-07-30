package systems.hugmesh.adminbff.web.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * One entry of a worklist batch ({@link BatchTriggerImageBuildRequest}) — a single image the
 * batch builds (one per role x platform). The trigger-shaped fields ({@code targetUser},
 * {@code imageType}, {@code sshKeysAllowed}) plus the ENUMERATED {@code hardwareClass}
 * (the worklist {@code platform} enum, which REPLACES today's free-text hardware class) and an
 * optional {@code imageSpec} — the MATERIALIZED flat per-image ImageConfig for the FULL
 * IMAGE_SPEC_JSON channel (item 1b).
 *
 * <p>SECURITY: there is intentionally NO {@code domain} field — a caller can never pick a
 * tenant. Every build's domain is SERVER-derived from the caller's validated issuer + the
 * own-domain wall in {@link systems.hugmesh.adminbff.imagegen.ImageBuildService}. The
 * {@code @Pattern}/{@code @NotBlank} guards make a malformed entry a clean 400 BEFORE any write;
 * the free-form {@code imageSpec} JsonNode is NOT trusted here — it is deep-validated by the
 * fail-closed worklist.v1 envelope validator (no SECRET_FIELDS, valid package atoms / domain
 * names) BEFORE it is ever persisted or written to a ConfigMap.
 *
 * <ul>
 *   <li>{@code targetUser} — the subject the image is FOR (own-domain-walled unless SUPERADMIN);
 *       same allowlist charset as the single-trigger DTO (substituted into a quoted YAML
 *       scalar, so quotes/newlines/controls are rejected).</li>
 *   <li>{@code imageType} — {@code primary} / {@code mesh-extension} / {@code client}.</li>
 *   <li>{@code hardwareClass} — the target PLATFORM, ENUMERATED to the six generator platforms
 *       (replaces the old free-text hardware class): {@code x86|rpi5|frite|jetson|orangepi5|
 *       orangepizero2}.</li>
 *   <li>{@code sshKeysAllowed} — may this build emit a downloadable non-secret keys bundle?
 *       Absent/null defaults to {@code false} (fail-closed).</li>
 *   <li>{@code imageSpec} — the MATERIALIZED flat ImageConfig for this image (secrets blanked);
 *       {@code null} keeps the LEGACY 6-env manifest path.</li>
 * </ul>
 */
public record BatchImageSpec(

        @NotBlank(message = "targetUser is required")
        @Size(max = 400, message = "targetUser is too long")
        @Pattern(regexp = "^[A-Za-z0-9._@/-]{1,400}$",
                message = "targetUser contains invalid characters")
        String targetUser,

        @NotBlank(message = "imageType is required")
        @Pattern(regexp = "primary|mesh-extension|client",
                message = "imageType must be primary, mesh-extension or client")
        String imageType,

        // The ENUMERATED platform (worklist WorklistEntry.platform), which replaces free-text
        // hardwareClass. Locked to the six generator platforms — a defence-in-depth twin of the
        // envelope validator's platform check and the renderManifest yamlSafe() scalar guard.
        @NotBlank(message = "hardwareClass (platform) is required")
        @Pattern(regexp = "x86|rpi5|frite|jetson|orangepi5|orangepizero2",
                message = "hardwareClass must be one of x86, rpi5, frite, jetson, orangepi5, orangepizero2")
        String hardwareClass,

        @Nullable
        Boolean sshKeysAllowed,

        @Nullable
        JsonNode imageSpec) {

    /** Fail-closed default: keys are NOT allowed unless explicitly requested true. */
    public boolean sshKeysAllowedOrFalse() {
        return Boolean.TRUE.equals(sshKeysAllowed);
    }

    /** The materialized spec serialized for the durable {@code image_spec_json} column /
     *  ConfigMap, or {@code null} for the legacy 6-env path. Compact single-line JSON (no
     *  literal newlines) — safe to embed in a YAML block scalar. */
    @Nullable
    public String imageSpecJson() {
        return imageSpec == null || imageSpec.isNull() ? null : imageSpec.toString();
    }
}
