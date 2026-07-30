package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/admin/domain-lock/{role}/{user}} — the OPTIONAL domain-lock
 * parameters (a reason). The authoritative {@code user} and {@code role} are carried as
 * PATH variables on the endpoint (and validated there: {@code @NotBlank user},
 * {@code @Pattern} role); the matching fields here are {@code @Nullable} mirrors for the
 * OpenAPI contract and the controller ignores them in favour of the path values. The
 * whole body is optional (a domain-lock needs no body at all).
 *
 * <p>This is a SEPARATE @Pattern from the suspension {@code ROLE_PATTERN} (do NOT widen
 * that closed vocabulary): the two ADDITIVE domain-locked MARKER roles are their own
 * closed set, matching the DB {@code ck_domain_lock_role} CHECK (changeset 009).
 *
 * <ul>
 *   <li>{@code user} — {@code @Nullable} mirror of the path variable (the path's
 *       {@code @NotBlank} is the real guard; validated for length only when present).</li>
 *   <li>{@code role} — {@code @Nullable} mirror; the {@code @Pattern} closed vocabulary
 *       {@code ROLE_MATRIX_DOMAINLOCKED|ROLE_MASTODON_DOMAINLOCKED} matches the DB
 *       CHECK.</li>
 *   <li>{@code reason} — OPTIONAL audit note.</li>
 * </ul>
 */
public record DomainLockRequest(
        @Size(max = 400, message = "user is too long")
        @Nullable
        String user,

        @Pattern(regexp = "ROLE_MATRIX_DOMAINLOCKED|ROLE_MASTODON_DOMAINLOCKED",
                 message = "role must be one of ROLE_MATRIX_DOMAINLOCKED, ROLE_MASTODON_DOMAINLOCKED")
        @Nullable
        String role,

        @Size(max = 1024, message = "reason is too long")
        @Nullable
        String reason) {
}
