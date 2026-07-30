package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code PUT /bff/superadmin/backing-services/{id}/mode} (SUPERADMIN + step-up) —
 * records ONE backing-service MODE intent in the {@code backing_service_mode} ledger (schema
 * 310). The {@code @NotBlank}/{@code @Size} guards make a malformed request a clean 400 (mapped
 * by {@link systems.hugmesh.adminbff.web.ValidationExceptionHandler}) BEFORE any write; the
 * vocabulary checks (mode {@code self-hosted}|{@code managed}, managed-requires-endpoint,
 * tier-3 docs-only refusal) are enforced in
 * {@link systems.hugmesh.adminbff.backingservices.BackingServiceService}.
 *
 * <p><b>NO SECRETS.</b> {@code endpoint} is a non-secret coordinate (a host/URL) and
 * {@code credsRef} is a REFERENCE only (an ESO/Vault path name) — there is deliberately NO field
 * for credential bytes. Operator-supplied managed-cloud credentials route to the generator side
 * (env -> keys-file -> ESO/Vault), never through the admin BFF.
 *
 * <ul>
 *   <li>{@code mode} — {@code self-hosted} (in-mesh default) | {@code managed} (hosted cloud).
 *       REQUIRED.</li>
 *   <li>{@code endpoint} — the managed service host/URL; REQUIRED for {@code managed}, ABSENT
 *       for {@code self-hosted}.</li>
 *   <li>{@code credsRef} — an ESO/Vault path NAME the managed creds are sourced from (a
 *       reference, never bytes); optional.</li>
 * </ul>
 */
public record SetBackingServiceModeRequest(
        @NotBlank(message = "mode is required ('self-hosted' or 'managed')")
        @Size(max = 16, message = "mode is too long")
        String mode,

        @Size(max = 512, message = "endpoint is too long")
        @Nullable
        String endpoint,

        @Size(max = 255, message = "credsRef is too long")
        @Nullable
        String credsRef) {
}
