package systems.hugmesh.adminbff.appeal;

import java.time.Instant;

/**
 * A single {@code account_appeal} row — a curtailed principal's structured appeal
 * against their OWN {@code access_suspension} {@code PROFILE} ban/suspension
 * (schema in Liquibase {@code db/changelog/250-account-appeals.xml}).
 *
 * <p>Distinct from federation-api's {@code ModerationRequest} (CONTENT moderation of
 * posts/profiles): this is the ACCOUNT-level appeal domain.
 *
 * <ul>
 *   <li>{@code userSub} — the appellant's own resolved {@code Account.id()} (owner ==
 *       subject; a user only ever sees/creates their OWN appeal rows).</li>
 *   <li>{@code handle} — the appellant's {@code Account.handle()}, the SAME identity
 *       string {@link systems.hugmesh.adminbff.suspension.SuspensionService} reads
 *       for {@code statusFor} and writes for {@code suspend}/{@code clear}. An APPROVE
 *       decide clears the {@code PROFILE} suspension for this exact handle.</li>
 *   <li>{@code status} — {@code PENDING} / {@code APPROVED} / {@code DENIED}.</li>
 * </ul>
 */
public record AccountAppeal(
        String id,
        String userSub,
        String handle,
        String domain,
        String reason,
        String contactEmail,
        String status,
        Instant submittedAt,
        Instant decidedAt,
        String decidedBy) {

    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_APPROVED = "APPROVED";
    public static final String STATUS_DENIED = "DENIED";
}
