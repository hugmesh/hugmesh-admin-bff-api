package net.hugmesh.adminbff.matrixadmin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Step 2 of the ADMIN Matrix deactivate: the SAME account named in the propose, and the token
 * the propose returned. {@code token} is not {@code @NotBlank} on purpose: a missing token is a
 * refusal the service audits ({@code no-token}), not a generic validation error.
 */
public record MatrixDeactivateConfirmRequest(@NotBlank @Size(max = 255) String mxid,
                                             @Size(max = 128) String token) {
}
