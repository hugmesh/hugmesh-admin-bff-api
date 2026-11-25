package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/internal/domains/{clusterDomain}/reconcile-ack} — the node agent's
 * report (hugmesh-generator {@code specs/usr/sbin/hugmesh-domain-reconcile}, {@code ack_generation},
 * which builds exactly {@code {caProvisioned, appsetRegistered, generation}} with {@code jq}).
 *
 * <p>{@code generation} is the EXPORT envelope's generation the agent verified and acted on
 * ({@code rv_gen} of the fetched export). It is stored as the row's
 * {@code last_reconciled_generation} only when it is strictly greater than the stored value.
 *
 * <p>{@code caProvisioned} is ACCEPTED so the agent's body validates as sent, and then IGNORED:
 * operator decision 87a = B makes the domain's CA an admin-bff Vault step, so a node's opinion
 * of whether a CA exists is not written to {@code ca_provisioned}.
 */
public record DomainReconcileAckRequest(
        /** Ignored (decision 87a = B); accepted so the agent's body is valid as sent. */
        @Nullable
        Boolean caProvisioned,

        /** Whether this node emitted the domain's brand-repo tree. */
        @NotNull(message = "appsetRegistered is required")
        Boolean appsetRegistered,

        /** The export generation the agent verified and acted on. */
        @NotNull(message = "generation is required")
        @PositiveOrZero(message = "generation must not be negative")
        Long generation) {
}
