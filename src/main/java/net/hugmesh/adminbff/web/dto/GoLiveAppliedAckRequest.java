package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/internal/go-live/{intentId}/applied-ack} — the HOST-SIDE go-live
 * agent's report that it verified the signed export (Ed25519 + strict-monotonic generation)
 * and wrote (or removed) the {@code /etc/hugmesh/go-live} marker for ONE intent entry.
 *
 * <p><b>Which "generation"? (load-bearing).</b> This is the intent ENTRY's own per-row
 * generation stamp — the {@code gen=} field the agent read off THAT entry's line in the
 * canonical export bytes ({@link
 * net.hugmesh.adminbff.golive.GoLiveExportModels.GoLiveIntentEntry#generation()}) —
 * NEVER the export envelope's top-level {@code generation}, which is {@code max(generation)}
 * over EVERY row in the ledger ({@link
 * net.hugmesh.adminbff.golive.GoLiveExportModels.GoLiveExportBody#generation()}).
 * Sending the envelope-level number here would defeat the CAS supersede guard — see {@link
 * net.hugmesh.adminbff.golive.GoLiveService#applyAck}.
 *
 * <ul>
 *   <li>{@code generation} — the intent row's OWN generation stamp. REQUIRED.</li>
 *   <li>{@code appliedBy} — the acking host's identity (e.g. a node/machine-key fingerprint).
 *       REQUIRED, non-secret.</li>
 * </ul>
 */
public record GoLiveAppliedAckRequest(
        @NotNull(message = "generation is required")
        @Positive(message = "generation must be the intent's own positive row generation stamp")
        Long generation,

        @NotBlank(message = "appliedBy is required")
        @Size(max = 255, message = "appliedBy is too long")
        String appliedBy) {
}
