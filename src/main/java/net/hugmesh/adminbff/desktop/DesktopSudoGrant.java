package net.hugmesh.adminbff.desktop;

import java.time.Instant;

/**
 * A single {@code desktop_sudo_grant} row — the per-(domain, subject, device) SSO-enforced
 * sudo grant (schema in Liquibase {@code db/changelog/140-desktop-app-governance.xml}).
 * CLONES {@link net.hugmesh.adminbff.device.SshLicense} EXACTLY in lifecycle shape.
 *
 * <p>DEFAULT NONE = no sudo: the desktop image bakes no sudoers; an ACTIVE grant is the
 * ONLY thing that confers sudo, and it does so by being emitted as a revocable SSO claim
 * (the {@code desktop-sudo} role/claim for that domain) the on-device PAM/polkit consults
 * at login. Revoking the grant (CAS {@code active -> revoked}, NEVER deleted = audit)
 * removes the claim at the next token refresh — centrally revocable at the IdP.
 *
 * <ul>
 *   <li>{@code subject} — the Casdoor subject granted sudo (the licensed desktop user).</li>
 *   <li>{@code deviceId} — the desktop device the grant applies on
 *       ({@code device_registry} id).</li>
 *   <li>{@code state} — {@code active} (grants sudo) / {@code revoked} (CAS, audited).</li>
 *   <li>{@code domain} — the brand the grant belongs to (stamped from the device's
 *       residency; the ADMIN read view scopes on it).</li>
 *   <li>{@code propagationState} — FIX-REVOKE: the push-with-ack outcome (IdP claim /
 *       on-device PAM) the UI surfaces.</li>
 *   <li>{@code generation} — monotonic, bumped on every mutate.</li>
 * </ul>
 */
public record DesktopSudoGrant(
        String id,
        String subject,
        String deviceId,
        String state,
        String grantedBy,
        Instant grantedAt,
        Instant revokedAt,
        String revokedBy,
        String domain,
        String propagationState,
        long generation) {

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_REVOKED = "revoked";

    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";
    public static final String PROP_DEGRADED = "degraded";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }
}
