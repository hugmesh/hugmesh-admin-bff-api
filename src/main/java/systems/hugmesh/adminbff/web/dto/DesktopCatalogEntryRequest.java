package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/admin/desktop/catalog} — add a Flatpak/OCI app ref to the
 * caller's brand Discover allowlist. The target domain is NEVER a body field (it is the
 * caller's validated-issuer brand); this carries only the ref + display + source.
 *
 * <ul>
 *   <li>{@code appRef} — the Flatpak/OCI reference (e.g. {@code org.mozilla.firefox}).</li>
 *   <li>{@code displayName} — the human label shown in Discover.</li>
 *   <li>{@code source} — optional {@code FLATPAK} (default) or {@code OCI}.</li>
 * </ul>
 */
public record DesktopCatalogEntryRequest(
        @NotBlank(message = "appRef is required")
        @Size(max = 512, message = "appRef is too long")
        // SECURITY: appRef is spliced into a remote-shell install command
        // (RestDesktopSshClient → session.exec). Restrict to a Flatpak/OCI-ref
        // charset — letters/digits and . _ + - / : @ only — so no shell
        // metacharacter, whitespace, or newline can ever reach the SSH command
        // (defence-in-depth for the dark remote-install path).
        @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9._+/:@-]*$",
                message = "appRef may contain only letters, digits and . _ + - / : @")
        String appRef,

        @NotBlank(message = "displayName is required")
        @Size(max = 256, message = "displayName is too long")
        String displayName,

        @Pattern(regexp = "(?i)FLATPAK|OCI", message = "source must be FLATPAK or OCI")
        String source) {
}
