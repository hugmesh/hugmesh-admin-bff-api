package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * Body for {@code POST /bff/superadmin/service-store/{domain}/deployments} (SUPERADMIN) —
 * record an ACTIVE deployment of a service in a brand/domain (schema 102).
 *
 * <p>NOTE: the {@code domain} is taken from the PATH (the superadmin's explicit target),
 * NEVER from this body. The {@code @NotBlank}/{@code @Size} guards make a malformed request
 * a clean 400 via {@link systems.hugmesh.adminbff.web.ValidationExceptionHandler} BEFORE
 * any write.
 *
 * <ul>
 *   <li>{@code serviceKey} — REQUIRED; the service being deployed.</li>
 *   <li>{@code profileRef} — nullable soft reference to an {@code app_profile.name} (the
 *       template stamped on the deployment).</li>
 *   <li>{@code endingAt} — the SINGLE expiry clock; {@code null} = no-expiry (a permanent
 *       deployment). When in the past the expiry loop ends it on the next tick.</li>
 *   <li>{@code enforceActions} — opaque JSON/CSV of the effects to EMIT at end-of-lease
 *       (e.g. {@code "teardown,revoke-roles,revoke-certs,alert"}); SHIPS DARK in PR1.</li>
 * </ul>
 */
public record ServiceDeploymentRequest(
        @NotBlank(message = "serviceKey is required")
        @Size(max = 128, message = "serviceKey is too long")
        String serviceKey,

        @Size(max = 128, message = "profileRef is too long")
        @Nullable
        String profileRef,

        @Nullable
        Instant endingAt,

        @Size(max = 4096, message = "enforceActions is too long")
        @Nullable
        String enforceActions) {
}
