package net.hugmesh.adminbff.tor;

import java.time.Instant;

/**
 * The SUPERADMIN's per-node Tor desired state (hugmesh-admin-bff-api#108), carried to the
 * node by the signed per-node export ({@link TorExportService}).
 *
 * @param machineKeyFp     the node's {@code device_registry.machine_key_fp}
 * @param upstreamManaged  {@code true} once a SUPERADMIN has set this node's upstream: the
 *                         export then tells the agent what {@code /etc/hugmesh/tor/upstream}
 *                         must hold. {@code false} = no runtime opinion (the agent keeps
 *                         the image's file, or a person's)
 * @param upstream         {@code host:port}, or {@code null} = the agent's built-in default
 *                         ({@code 127.0.0.1:443}: the agent removes the file)
 * @param configGeneration bumps on every write to this node's row
 * @param updatedBy        the SUPERADMIN who last wrote it
 * @param updatedAt        when
 */
public record TorNodeConfig(
        String machineKeyFp,
        boolean upstreamManaged,
        String upstream,
        long configGeneration,
        String updatedBy,
        Instant updatedAt) {
}
