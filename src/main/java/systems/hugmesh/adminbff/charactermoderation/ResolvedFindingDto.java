package systems.hugmesh.adminbff.charactermoderation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * One resolved moderation finding as returned by hugmesh-federation-api's
 * {@code GET /api/federation/findings/resolved} (#71). Matched field-for-field to that
 * contract:
 *
 * <pre>{ id, surface, subjectRef, status, reviewer, domain, ts }</pre>
 *
 * <ul>
 *   <li>{@code id} — the federation finding id; the STRICT {@code id>sinceId} cursor key
 *       (the list is returned id ASC).</li>
 *   <li>{@code surface} — {@code character-part} | {@code character-sticker} (echoes the
 *       query filter).</li>
 *   <li>{@code subjectRef} — the user-bff row id the finding is about (the {@code {id}}
 *       path segment the sink flips). For a part this is the {@code vn_character_part}
 *       id; for a sticker the sticker row id.</li>
 *   <li>{@code status} — {@code actioned} (the content was removed → REJECTED) or
 *       {@code dismissed} (the report was rejected, content is fine → ACTIVE). See
 *       {@link FindingActivationReconciler} for the status→ACTIVE/REJECTED mapping.</li>
 *   <li>{@code reviewer} — the resolving moderator (forwarded to the sink for audit).</li>
 *   <li>{@code domain} — the finding's brand (informational; the sink derives tenancy
 *       from the row, not this field).</li>
 *   <li>{@code ts} — the resolution timestamp (informational).</li>
 * </ul>
 *
 * <p>{@code @JsonIgnoreProperties(ignoreUnknown=true)} so a federation-side additive field
 * never breaks the poll (forward-compatible contract read).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ResolvedFindingDto(
        Long id,
        String surface,
        Long subjectRef,
        String status,
        String reviewer,
        String domain,
        String ts) {

    /** federation status: the content was actioned/removed. Maps to user-bff REJECTED. */
    public static final String STATUS_ACTIONED = "actioned";
    /** federation status: the report was dismissed (content is fine). Maps to user-bff ACTIVE. */
    public static final String STATUS_DISMISSED = "dismissed";

    /** True iff this finding carries the minimum the sink push needs (id + subjectRef + a
     *  recognised status). A malformed row is skipped (and HALTS the cursor) rather than
     *  pushed with junk. */
    public boolean isPushable() {
        return id != null && subjectRef != null
                && (STATUS_ACTIONED.equals(status) || STATUS_DISMISSED.equals(status));
    }
}
