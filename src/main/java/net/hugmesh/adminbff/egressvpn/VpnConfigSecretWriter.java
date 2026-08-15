package net.hugmesh.adminbff.egressvpn;

import reactor.core.publisher.Mono;

/**
 * The RUNTIME delivery seam for an imported egress-VPN config's bytes — the K8s Secret leg
 * {@code docs/EGRESS-VPN.md} (generator) promises: "The runtime UI path instead delivers a
 * config as a K8s Secret; Postgres holds only {@code secret_ref} + metadata". The import flow
 * parses + validates the posted {@code .conf}/{@code .ovpn}, stores the metadata row, and hands
 * the RAW BYTES to this seam — which either persists them as the Secret the node-level
 * {@code hugmesh-vpn-reconcile} agent reads (the real fabric8 writer) or drops them dark (the
 * Noop, the DEFAULT).
 *
 * <h3>Secret contract (what the node agent anticipates)</h3>
 * The agent resolves each export entry's bytes at {@code ${VPN_SECRET_DIR}/<secretRef>} — a
 * file NAMED BY the {@code secretRef}. A default (item-map-free) Secret volume projection
 * yields one file PER DATA KEY, so the Secret is:
 * <ul>
 *   <li><b>name</b> = the row's {@code secretRef} (default {@code egress-vpn-<domain>-<name>},
 *       stamped by {@link EgressVpnController#importConfig});</li>
 *   <li><b>data key</b> = the {@code secretRef} again (so the default projection materialises
 *       exactly the {@code ${SECRET_DIR}/<secretRef>} path the agent reads);</li>
 *   <li><b>value</b> = the raw config text (the private VPN key rides here, NEVER the DB).</li>
 * </ul>
 *
 * <h3>Best-effort, fail-open-to-key-USB</h3>
 * A failed write NEVER fails the import: the config row (the audit/control record) is already
 * committed, the row's {@code propagationState} stays {@code pending} (visibly un-applied in
 * the UI), and the node agent falls back to the key-USB-provisioned config when no Secret is
 * mounted. Implementations therefore swallow cluster errors to {@code false}.
 *
 * <p><b>REDACTION:</b> implementations MUST NOT log/echo the config body (it contains the
 * private VPN key) — only its length and the non-secret naming metadata.
 */
public interface VpnConfigSecretWriter {

    /**
     * Persist (create-or-update) the Secret for one imported config. Returns {@code true}
     * when the Secret was actually applied, {@code false} on the dark Noop or a swallowed
     * cluster failure. Never errors.
     */
    Mono<Boolean> write(String secretRef, String domain, String name, String kind, String configBody);

    /** {@code true} only for the real cluster-dialing writer (the wiring tests' probe). */
    boolean isReal();
}
