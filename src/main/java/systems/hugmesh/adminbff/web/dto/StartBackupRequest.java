package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Body for {@code POST /bff/admin/backups} (start a backup).
 *
 * <p>{@code scope} is the non-empty list of things to back up (each validated
 * against the closed {@link systems.hugmesh.adminbff.backup.BackupScope}
 * vocabulary in the service — a bad scope name is a 400 there). {@code target} is
 * {@code CLUSTER} or {@code USB} (DB-CHECK-parity enum); a {@code USB} target also
 * requires {@code usbDeviceId}. {@code encrypt=true} requires {@code password}.
 *
 * <p>SECURITY: {@code password} is bean-validated for length only and is NEVER
 * logged or persisted — the controller hands it straight to the service, which
 * uses it to derive a PBKDF2 verifier (stored) and to seed the worker's ephemeral
 * Secret (transient). It carries no {@code toString} exposure beyond the record's
 * default, which the controller never logs.
 */
public record StartBackupRequest(
        @NotEmpty(message = "at least one scope is required")
        List<@Pattern(regexp = "(?i)etcd|secrets|postgres|pvc|config",
                message = "scope must be one of etcd, secrets, postgres, pvc, config") String> scope,

        @NotNull(message = "target is required")
        @Pattern(regexp = "(?i)CLUSTER|USB", message = "target must be CLUSTER or USB")
        String target,

        @Size(max = 200, message = "usbDeviceId is too long")
        String usbDeviceId,

        boolean encrypt,

        @Size(min = 8, max = 256, message = "password must be 8–256 characters")
        String password) {
}
