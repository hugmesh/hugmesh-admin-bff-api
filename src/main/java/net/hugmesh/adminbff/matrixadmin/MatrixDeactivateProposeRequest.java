package net.hugmesh.adminbff.matrixadmin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Step 1 of the ADMIN Matrix deactivate: the account to propose deactivating — a full MXID
 * ({@code @alice:hugmesh.net}) or a bare localpart qualified to the configured server name.
 */
public record MatrixDeactivateProposeRequest(@NotBlank @Size(max = 255) String mxid) {
}
