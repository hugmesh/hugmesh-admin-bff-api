package systems.hugmesh.adminbff.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * Wire shape of a hugmesh-federation-api {@code moderation_requests} row, matched
 * FIELD-FOR-FIELD to federation-api
 * {@code systems.hugmesh.federation.model.ModerationRequest} (whose Jackson
 * serialisation uses its getters → these exact field names): {@code id, requester,
 * kind, target, reason, status, modReferrer, adminDecider, ts, domain}.
 *
 * <ul>
 *   <li>{@code kind}   — {@code 'instance-block' | 'user-removal'}</li>
 *   <li>{@code status} — {@code 'recommended' | 'referred' | 'approved' | 'denied'}
 *       ({@code approved}/{@code denied} after an admin decision)</li>
 * </ul>
 *
 * <p>A record (immutable DTO); {@code @JsonIgnoreProperties} keeps the admin-bff
 * forward-compatible if federation-api adds a field.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ModerationDecisionDto(
        Long id,
        String requester,
        String kind,
        String target,
        String reason,
        String status,
        String modReferrer,
        String adminDecider,
        Instant ts,
        String domain
) {}
