package net.hugmesh.adminbff.desktop;

import java.time.Instant;

/**
 * A single {@code desktop_install_request} row — a non-sudo user's request that an admin
 * allow/install an app on their device (schema in Liquibase
 * {@code db/changelog/140-desktop-app-governance.xml}).
 *
 * <p>{@code requester} is the JWT SUBJECT (owner == subject, fail-closed) and {@code domain}
 * is stamped from the validated issuer — a user can only create + see their OWN requests in
 * their OWN brand. An admin decision (approve/deny/installed) stamps {@code decidedBy} +
 * {@code decidedAt}. NEVER deleted = audit.
 *
 * <ul>
 *   <li>{@code status} — {@code pending} / {@code approved} / {@code denied} /
 *       {@code installed}.</li>
 *   <li>{@code domain} — the brand the request belongs to (the read scope predicate).</li>
 * </ul>
 */
public record DesktopInstallRequest(
        String id,
        String requester,
        String appRef,
        String deviceId,
        String status,
        String decidedBy,
        Instant decidedAt,
        String domain,
        Instant createdAt) {

    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_APPROVED = "approved";
    public static final String STATUS_DENIED = "denied";
    public static final String STATUS_INSTALLED = "installed";
}
