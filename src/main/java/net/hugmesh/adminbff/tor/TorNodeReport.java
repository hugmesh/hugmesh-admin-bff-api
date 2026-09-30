package net.hugmesh.adminbff.tor;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/**
 * What one tor-selected node says it exports (hugmesh-admin-bff-api#108): its PRIMARY v3
 * onion ({@code /var/lib/hugmesh/tor/hostname}) and one onion per Tor domain
 * ({@code /var/lib/hugmesh/tor/<slug>.hostname}), keyed by slug and sorted.
 *
 * <p>TELEMETRY, not authority: the node reports it over the {@code /bff/internal/**}
 * SERVICE channel, which any holder of the internal credential can reach, so nothing here
 * is ever used to decide access. It is shown to operators ({@link TorNodeView}).
 *
 * @param machineKeyFp   the fingerprint the node reports as its own
 * @param primaryOnion   the mesh's primary onion on this node, or {@code null} before mint
 * @param domainOnions   {@code slug -> onion}, sorted by slug; empty when none
 * @param firstReportedAt first report
 * @param lastReportedAt  latest report
 * @param reportCount     how many reports this fingerprint has sent
 */
public record TorNodeReport(
        String machineKeyFp,
        String primaryOnion,
        Map<String, String> domainOnions,
        Instant firstReportedAt,
        Instant lastReportedAt,
        long reportCount) {

    public TorNodeReport {
        domainOnions = domainOnions == null ? Map.of() : Collections.unmodifiableMap(new TreeMap<>(domainOnions));
    }

    /**
     * The stored form of {@code domainOnions}: one {@code <slug> <onion>} line per entry,
     * sorted by slug, each ending in a newline — the same spelling as the Go-Live
     * {@code domain-onions.txt}. Empty map -> empty string.
     */
    static String encodeDomainOnions(Map<String, String> domainOnions) {
        if (domainOnions == null || domainOnions.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : new TreeMap<>(domainOnions).entrySet()) {
            sb.append(e.getKey()).append(' ').append(e.getValue()).append('\n');
        }
        return sb.toString();
    }

    /** Inverse of {@link #encodeDomainOnions}; a line that is not {@code <slug> <onion>} is skipped. */
    static Map<String, String> decodeDomainOnions(String stored) {
        TreeMap<String, String> out = new TreeMap<>();
        if (stored == null || stored.isEmpty()) {
            return out;
        }
        for (String line : stored.split("\n")) {
            String[] parts = line.split(" ");
            if (parts.length == 2 && !parts[0].isEmpty() && !parts[1].isEmpty()) {
                out.put(parts[0], parts[1]);
            }
        }
        return out;
    }
}
