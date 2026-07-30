package systems.hugmesh.adminbff.announcement;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * One row of {@code announcement} (Liquibase changeset 060) — an admin-authored
 * site announcement. The JSON shape is what the admin-ui announcements view (CRUD)
 * and the home / login / forum surface banners read.
 *
 * <p>An announcement may show on any combination of four surfaces via the
 * per-surface flags: the logged-in HOME top banner ({@code targetHome}), the public
 * LOGIN page shown to anonymous visitors ({@code targetLogin}), akkoma as a
 * LOCAL-ONLY instance announcement ({@code targetAkkoma}), and the FORUM main page
 * ({@code targetForum}).
 *
 * <p>Security: {@code bodyHtml} is admin HTML rendered to users INCLUDING anonymous
 * login-page visitors; it is SANITISED server-side (jsoup Safelist) at create/update
 * BEFORE it is persisted (see {@link AnnouncementSanitizer}) and the UIs additionally
 * render it inside a sandboxed null-origin srcdoc iframe. {@code state}/{@code format}
 * are closed enums mirrored by DB CHECK constraints (the platform's API↔DB parity
 * rule). {@code akkomaRef} is the id of the akkoma announcement created on publish
 * (so it can be removed on unpublish/archive/expire/delete) and is never serialised
 * to the UI.
 *
 * <p>ACTIVE (per surface) = {@code state == 'published'} AND now within
 * {@code [startsAt, endsAt]} (NULL {@code startsAt} = now, NULL {@code endsAt} =
 * open) AND the relevant {@code target*} flag is true.
 *
 * <p>MULTI-TENANCY: {@code domain} is the brand/tenant discriminator (changeset 061)
 * — stamped on every row at create from the acting principal's validated JWT issuer
 * via {@link systems.hugmesh.commons.security.PrincipalDomain}. The ADMIN read/write
 * surface filters on {@code WHERE domain = :domain}; SUPERADMIN is unscoped. The
 * surface-feed endpoints (home/login/forum) remain unscoped because the login feed is
 * public/unauthenticated. {@code domain} is not exposed in the JSON response.
 */
public record Announcement(
        String id,
        String title,
        @JsonProperty("body_html") String bodyHtml,
        String format,
        String state,
        @JsonProperty("target_home") boolean targetHome,
        @JsonProperty("target_login") boolean targetLogin,
        @JsonProperty("target_akkoma") boolean targetAkkoma,
        @JsonProperty("target_forum") boolean targetForum,
        int priority,
        @JsonProperty("starts_at") Instant startsAt,
        @JsonProperty("ends_at") Instant endsAt,
        String timezone,
        boolean dismissible,
        @JsonProperty("created_by") String createdBy,
        // The akkoma announcement id is an internal propagation handle (used to
        // REMOVE the akkoma post on unpublish/archive/expire/delete); it is never
        // surfaced to the UI.
        @com.fasterxml.jackson.annotation.JsonIgnore String akkomaRef,
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("updated_at") Instant updatedAt,
        // Tenant discriminator: stamped on write, used as a WHERE predicate on the
        // ADMIN read surface. Not exposed in the JSON response.
        @com.fasterxml.jackson.annotation.JsonIgnore String domain) {
}
