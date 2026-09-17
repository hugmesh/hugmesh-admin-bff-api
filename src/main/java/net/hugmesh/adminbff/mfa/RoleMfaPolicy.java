package net.hugmesh.adminbff.mfa;

import java.time.LocalDateTime;
import java.util.List;

/**
 * The EFFECTIVE per-(domain, role) MFA policy the platform will act on — a stored
 * {@code role_mfa_policy} row when one exists, otherwise the built-in default for the role,
 * with the non-relaxable privileged floor applied on top in both cases.
 *
 * @param domain       the tenant discriminator the policy is scoped to
 * @param role         lowercase Casdoor role name
 * @param required     whether MFA is required for the role (post-floor)
 * @param methods      allowed methods; EMPTY means any ({@code NULL} in the row)
 * @param graceSeconds re-prompt grace window; {@code 0} = always re-prompt
 * @param fromRow      {@code true} iff a stored row backs this policy (vs. the built-in default)
 * @param floor        {@code true} iff the role is on the privileged floor, i.e. {@code required}
 *                     is pinned {@code true} regardless of any row (superadmin / admin)
 * @param updatedBy    who last wrote the row; {@code null} for a default
 * @param updatedAt    when the row was last written; {@code null} for a default or a never-updated row
 */
public record RoleMfaPolicy(
        String domain,
        String role,
        boolean required,
        List<String> methods,
        long graceSeconds,
        boolean fromRow,
        boolean floor,
        String updatedBy,
        LocalDateTime updatedAt) {

    public RoleMfaPolicy {
        methods = methods == null ? List.of() : List.copyOf(methods);
    }
}
