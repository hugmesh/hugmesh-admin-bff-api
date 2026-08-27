package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code PUT /bff/superadmin/optional-services/{slug}} (SUPERADMIN) — set ONE optional
 * cluster service's runtime {@code spec.enabled} on its {@code OptionalService}
 * ({@code platform.hugmesh.net/v1alpha1}) CR, which the Lease-gated
 * {@link net.hugmesh.adminbff.optionalservices.OptionalServiceReconciler} then converges onto
 * the {@code apps/13a} ApplicationSet element + the {@code installed-services} greying boolean.
 *
 * <p>The slug is a PATH variable, never a body field: it is intrinsic to the resource (the CRD
 * pins {@code spec.slug} immutable with a CEL rule) and the controller resolves
 * namespace/path/mountAt from its built-in
 * {@link net.hugmesh.adminbff.optionalservices.OptionalServiceRegistry}, so an admin can never
 * repoint a slug at an arbitrary manifest path.
 *
 * <ul>
 *   <li>{@code enabled} — REQUIRED. {@code true} installs (ApplicationSet creates
 *       {@code optional-<slug>}); {@code false} removes (the selector drops the element and
 *       ArgoCD prunes the Application).</li>
 *   <li>{@code reason} — optional audit text written to {@code spec.reason} and surfaced in the
 *       CR's events/status. Capped at 512 to match the CRD's {@code maxLength}, so an
 *       over-long reason is a clean 400 here instead of an API-server rejection later.</li>
 * </ul>
 */
public record SetOptionalServiceEnabledRequest(
        @NotNull(message = "enabled is required (true or false)")
        Boolean enabled,

        @Size(max = 512, message = "reason is too long (the CRD caps spec.reason at 512)")
        @Nullable
        String reason) {
}
