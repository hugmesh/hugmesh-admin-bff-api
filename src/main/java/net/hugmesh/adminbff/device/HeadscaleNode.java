package net.hugmesh.adminbff.device;

/**
 * One headscale-enrolled node as surfaced by {@code headscale nodes list -o json}, reduced
 * to the fields the device-license-registry PENDING flow needs. Headscale is the trust gate
 * that MINTS machine keys, so it is the authority for "what fingerprint is actually enrolled".
 *
 * <ul>
 *   <li>{@link #machineKeyFp()} — the CANONICAL fingerprint string, read from whichever JSON
 *       field {@link RegistryHeadscaleProperties#getFpField()} names (machineKey vs nodeKey;
 *       ⚠ the canonical choice is unconfirmed in CI — see {@code docs/CANONICAL-FP.md}). This
 *       is the OPAQUE token the pick-list carries and register re-validates — never typed,
 *       never normalised.</li>
 *   <li>{@link #hostname()} — the headscale-reported hostname, shown in the pick-list so a
 *       superadmin can recognise the physical node.</li>
 *   <li>{@link #user()} — the headscale OIDC user the node enrolled under (per-tenant Casdoor
 *       user in the target design); surfaced for the pick-list, advisory only.</li>
 *   <li>{@link #meshId()} — best-effort mesh identifier (the node's first tag, or the user);
 *       compared at register against the supplied meshId (fail-closed when enforcing).</li>
 * </ul>
 */
public record HeadscaleNode(
        String machineKeyFp,
        String hostname,
        String user,
        String meshId) {
}
