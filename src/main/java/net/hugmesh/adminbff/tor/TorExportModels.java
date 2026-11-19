package net.hugmesh.adminbff.tor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The wire shapes of the signed PER-NODE Tor export, {@code GET /bff/admin/tor/export?node=}
 * (hugmesh-admin-bff-api#108). CLONES {@link net.hugmesh.adminbff.egressvpn.VpnExportModels}:
 * a detached Ed25519 signature over a canonical line-oriented body, verified by the node
 * agent against the key-USB public half it bakes, with a monotonic generation for its
 * rollback guard.
 *
 * <p>This export is how a node's {@code /etc/hugmesh/tor/upstream} and
 * {@code /etc/hugmesh/tor/domains} get a runtime writer. The BFF never touches a node file:
 * the node agent fetches, verifies and writes. Each file has a {@code *Managed} flag, so
 * the agent can tell "write this" from "no runtime opinion, keep the image's file".
 */
public final class TorExportModels {

    private TorExportModels() {
    }

    /**
     * The canonical (pre-signature) per-node export body.
     *
     * @param node            the addressed node's {@code machine_key_fp}; empty on the
     *                        fail-closed body for an unknown fingerprint
     * @param generation      the node's {@code config_generation} PLUS the highest
     *                        generation among the {@code tor-onion} capability rows. Both
     *                        terms only grow, so any change either side makes strictly
     *                        advances the sum
     * @param upstreamManaged {@code true}: {@code /etc/hugmesh/tor/upstream} must hold
     *                        {@code upstream} (or be absent when {@code upstream} is empty).
     *                        {@code false}: leave the file alone
     * @param upstream        {@code host:port}, or empty for the agent's built-in default
     * @param domainsManaged  {@code true} once a SUPERADMIN has written the {@code ' global'}
     *                        {@code tor-onion} capability row: {@code /etc/hugmesh/tor/domains}
     *                        must hold exactly {@code domains}, one slug per line (empty =
     *                        withdraw every per-domain onion; the primary is unaffected).
     *                        {@code false}: leave the file alone
     * @param domains         the Tor domain slugs, sorted and de-duplicated, each matching
     *                        the agent's {@code [a-z0-9][a-z0-9-]{0,62}}
     * @param rotations       hugmesh-generator#652: one entry per listed domain a new onion
     *                        address was asked for (count above 0), sorted by slug. The node
     *                        agent rotates a domain whose count is above the one it last
     *                        applied. Empty adds nothing to the canonical bytes, so a body
     *                        with no request is byte-identical to before this field existed
     */
    public record TorExportBody(
            String node,
            long generation,
            boolean upstreamManaged,
            String upstream,
            boolean domainsManaged,
            List<String> domains,
            List<TorRotation> rotations) {

        public TorExportBody {
            domains = domains == null ? null : Collections.unmodifiableList(new ArrayList<>(domains));
            rotations = rotations == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(rotations));
        }

        /** A body with no rotation request (every caller before #652). */
        public TorExportBody(String node, long generation, boolean upstreamManaged, String upstream,
                             boolean domainsManaged, List<String> domains) {
            this(node, generation, upstreamManaged, upstream, domainsManaged, domains, List.of());
        }
    }

    /** One domain's new-address request count (hugmesh-generator#652). */
    public record TorRotation(String slug, long count) {
    }

    /**
     * The signed envelope. Mirrors {@code SignedVpnExport}: {@code contentHash} is
     * SHA-256 of the canonical body bytes; {@code signature} is the detached Ed25519 over
     * them (base64), or {@code null} when no signing key is configured, in which case the
     * agent must fail closed and change nothing.
     */
    public record SignedTorExport(
            TorExportBody body,
            String contentHash,
            String signature,
            String publicKey,
            boolean signed) {
    }
}
