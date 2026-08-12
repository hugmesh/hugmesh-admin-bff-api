package net.hugmesh.adminbff.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;

/**
 * Body for {@code POST /bff/admin/announcements} (create) and
 * {@code PUT /bff/admin/announcements/{id}} (update). The JSON field names match the
 * shared announcement contract (snake_case {@code body_html} / {@code target_*} /
 * {@code starts_at} / {@code ends_at}).
 *
 * <p>jakarta Bean Validation enforces the field-level rules (a violation → a clean
 * 400 {@code {error,fields}} via {@code ValidationExceptionHandler}):
 * <ul>
 *   <li>{@code title} required + length-bounded to the column width;</li>
 *   <li>{@code body_html} required + length-bounded (sanitised server-side before
 *       storage — see {@code AnnouncementSanitizer});</li>
 *   <li>{@code format} ∈ {html, wysiwyg} (defaulted at the controller when null);</li>
 *   <li>{@code state} ∈ {draft, published, archived} (defaulted to draft);</li>
 *   <li>{@code timezone} length-bounded.</li>
 * </ul>
 * The cross-field rules the annotations cannot express — at-least-one target flag,
 * and {@code starts_at < ends_at} — are enforced in
 * {@code AnnouncementService.validate} and surfaced as a 400 in the same
 * {@code {error,fields}} shape.
 */
public record AnnouncementRequest(
        @NotBlank(message = "title is required")
        @Size(max = 300, message = "title is too long")
        String title,

        @JsonProperty("body_html")
        @NotBlank(message = "body_html is required")
        @Size(max = 100_000, message = "body_html is too long")
        String bodyHtml,

        @Pattern(regexp = "html|wysiwyg", message = "format must be html or wysiwyg")
        String format,

        @Pattern(regexp = "draft|published|archived", message = "state must be draft, published or archived")
        String state,

        @JsonProperty("target_home") Boolean targetHome,
        @JsonProperty("target_login") Boolean targetLogin,
        @JsonProperty("target_akkoma") Boolean targetAkkoma,
        @JsonProperty("target_forum") Boolean targetForum,

        Integer priority,

        @JsonProperty("starts_at") Instant startsAt,
        @JsonProperty("ends_at") Instant endsAt,

        @Size(max = 64, message = "timezone is too long")
        String timezone,

        Boolean dismissible) {
}
