package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/admin/access-roles/{role}/{user}} — the OPTIONAL
 * suspension parameters (a TTL + a reason). The authoritative {@code user} and
 * {@code role} are carried as PATH variables on the endpoint (and validated there:
 * {@code @NotBlank user}, {@code @Pattern} role); the matching fields here are
 * {@code @Nullable} mirrors for non-path callers / the OpenAPI contract and the
 * controller ignores them in favour of the path values. The whole body is optional
 * (a permanent suspension needs no body at all).
 *
 * <ul>
 *   <li>{@code user} — {@code @Nullable} mirror of the path variable (the path's
 *       {@code @NotBlank} is the real guard; validated for length only when present).</li>
 *   <li>{@code role} — {@code @Nullable} mirror; the {@code @Pattern} closed
 *       vocabulary {@code ROLE_MATRIX|ROLE_MASTODON|ROLE_MESH|PROFILE} matches the DB
 *       {@code ck_access_suspension_role} CHECK (created by changeset 008, widened
 *       with {@code ROLE_MESH} by changeset 330).</li>
 *   <li>{@code ttlSeconds} — OPTIONAL: null/absent = PERMANENT (expires_at NULL); a
 *       present value must be {@code @Positive}.</li>
 *   <li>{@code reason} — OPTIONAL audit note.</li>
 * </ul>
 */
public record SuspensionRequest(
        @Size(max = 400, message = "user is too long")
        @Nullable
        String user,

        @Pattern(regexp = "ROLE_MATRIX|ROLE_MASTODON|ROLE_MESH|PROFILE",
                 message = "role must be one of ROLE_MATRIX, ROLE_MASTODON, ROLE_MESH, PROFILE")
        @Nullable
        String role,

        @Positive(message = "ttlSeconds must be a positive number of seconds")
        @Nullable
        Long ttlSeconds,

        @Size(max = 1024, message = "reason is too long")
        @Nullable
        String reason) {
}
