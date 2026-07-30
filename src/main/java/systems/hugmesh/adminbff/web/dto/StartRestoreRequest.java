package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Body for {@code POST /bff/admin/restores} (start a restore).
 *
 * <p>{@code backupId} identifies the source row in {@code backup_history} (a USB
 * backup is surfaced through the same history once discovered). {@code scope} is
 * OPTIONAL — when omitted the source backup's own scope is restored; when present
 * it narrows the restore and is validated against the closed vocabulary in the
 * service. {@code password} is required (and verified) only when the source is
 * encrypted; a wrong password is a 403 and the key is never revealed.
 *
 * <p>SECURITY: {@code password} is length-validated only and never logged/persisted.
 */
public record StartRestoreRequest(
        @NotBlank(message = "backupId is required")
        @Pattern(regexp = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                message = "backupId must be a UUID")
        String backupId,

        List<@Pattern(regexp = "(?i)etcd|secrets|postgres|pvc|config",
                message = "scope must be one of etcd, secrets, postgres, pvc, config") String> scope,

        @Size(min = 8, max = 256, message = "password must be 8–256 characters")
        String password) {
}
