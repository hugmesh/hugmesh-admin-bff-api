package net.hugmesh.adminbff.tor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One row of {@code GET /bff/admin/tor/nodes}: a node's exported onions as
 * {@code {primary, domains: {slug: onion}}} (the shape hugmesh-admin-bff-api#108 asks for),
 * joined with the registry and the node's Tor desired state.
 *
 * <p>For a SUPERADMIN every field is filled. For a domain ADMIN the row is REDACTED to that
 * admin's own domain: {@code domains} holds at most the admin's own slug, {@code primary}
 * is shown only to the {@code default} domain (the primary onion is the default brand's
 * door), and every node-identity and routing field ({@code node}, {@code hostname},
 * {@code residencyDomain}, {@code upstream}) is {@code null}. See
 * {@link TorNodeService#list}.
 *
 * @param node             the reporting node's {@code machine_key_fp}
 * @param hostname         the registry hostname, or {@code null} if unregistered
 * @param residencyDomain  the registry residency domain, or {@code null} if unregistered
 * @param registered       whether the fingerprint is in {@code device_registry}
 * @param primary          the primary onion, or {@code null}
 * @param domains          {@code slug -> onion}, sorted by slug
 * @param upstreamManaged  whether the export manages this node's upstream file
 * @param upstream         the managed upstream ({@code null} = the agent's default)
 * @param configGeneration this node's config generation (0 = never configured)
 * @param lastReportedAt   the latest report, or {@code null} if the node never reported
 * @param reportCount      reports received from this fingerprint
 */
public record TorNodeView(
        String node,
        String hostname,
        String residencyDomain,
        boolean registered,
        String primary,
        Map<String, String> domains,
        boolean upstreamManaged,
        String upstream,
        long configGeneration,
        Instant lastReportedAt,
        long reportCount) {

    public TorNodeView {
        domains = domains == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(domains));
    }
}
