package systems.hugmesh.adminbff.egressvpn;

/**
 * Parse + VALIDATE a provider-uploaded VPN config (ProtonVPN WireGuard {@code .conf}
 * FIRST-CLASS; OpenVPN {@code .ovpn} fallback) into the {@link Parsed} metadata the
 * control plane stores — WITHOUT persisting the raw bytes (the {@code .conf}/{@code .ovpn}
 * — including the private key — rides the K8s Secret via ESO, never this database).
 *
 * <p>A malformed config is an {@link IllegalArgumentException} (the controller maps it to
 * a clean 422, never a silently-broken config row). The required structure is the minimum
 * a node's {@code wg-quick} / {@code openvpn} actually needs:
 * <ul>
 *   <li>WireGuard: an {@code [Interface]} section with a {@code PrivateKey} AND a
 *       {@code [Peer]} section with a {@code PublicKey} + an {@code Endpoint}.</li>
 *   <li>OpenVPN: a {@code remote &lt;host&gt; &lt;port&gt;} directive.</li>
 * </ul>
 * Only the non-secret {@code Endpoint}/{@code remote} is surfaced (as display metadata);
 * the {@code PrivateKey} is matched for presence but NEVER returned or logged.
 */
public final class VpnConfigParser {

    private VpnConfigParser() {
    }

    /** The non-secret metadata extracted from a config: its kind + display endpoint. */
    public record Parsed(String kind, String endpoint) {
    }

    /**
     * Sniff + validate the config text. The {@code kind} hint (from the upload's content
     * type / filename) is advisory; the body content decides. Throws
     * {@link IllegalArgumentException} on any malformed/incomplete config.
     */
    public static Parsed parse(String body) {
        if (body == null || body.isBlank()) {
            throw new IllegalArgumentException("VPN config is empty");
        }
        String trimmed = body.strip();
        // WireGuard configs carry an [Interface] section; OpenVPN configs carry a
        // `remote ...` directive. Prefer WireGuard when both somehow appear.
        boolean looksWg = trimmed.toLowerCase().contains("[interface]");
        if (looksWg) {
            return parseWireguard(trimmed);
        }
        if (containsRemoteDirective(trimmed)) {
            return parseOpenvpn(trimmed);
        }
        throw new IllegalArgumentException(
                "unrecognised VPN config: expected a WireGuard [Interface]/[Peer] config "
                + "(ProtonVPN .conf) or an OpenVPN config with a 'remote' directive");
    }

    private static Parsed parseWireguard(String body) {
        boolean hasInterface = false;
        boolean hasPrivateKey = false;
        boolean hasPeer = false;
        boolean hasPeerPublicKey = false;
        String endpoint = null;
        String section = "";
        for (String raw : body.split("\\R")) {
            String line = stripComment(raw).trim();
            if (line.isEmpty()) continue;
            if (line.startsWith("[") && line.endsWith("]")) {
                section = line.toLowerCase();
                if (section.equals("[interface]")) hasInterface = true;
                if (section.equals("[peer]")) hasPeer = true;
                continue;
            }
            String[] kv = splitKv(line);
            if (kv == null) continue;
            String key = kv[0].toLowerCase();
            String val = kv[1];
            if (section.equals("[interface]") && key.equals("privatekey") && !val.isBlank()) {
                hasPrivateKey = true; // presence ONLY — never captured/returned/logged
            }
            if (section.equals("[peer]") && key.equals("publickey") && !val.isBlank()) {
                hasPeerPublicKey = true;
            }
            if (section.equals("[peer]") && key.equals("endpoint") && !val.isBlank()) {
                endpoint = val;
            }
        }
        if (!hasInterface || !hasPrivateKey) {
            throw new IllegalArgumentException(
                    "invalid WireGuard config: an [Interface] section with a PrivateKey is required");
        }
        if (!hasPeer || !hasPeerPublicKey || endpoint == null) {
            throw new IllegalArgumentException(
                    "invalid WireGuard config: a [Peer] section with a PublicKey and an Endpoint is required");
        }
        return new Parsed(VpnConfig.KIND_WIREGUARD, endpoint);
    }

    private static Parsed parseOpenvpn(String body) {
        for (String raw : body.split("\\R")) {
            String line = stripComment(raw).trim();
            if (line.toLowerCase().startsWith("remote ")) {
                String[] parts = line.split("\\s+");
                if (parts.length >= 3) {
                    return new Parsed(VpnConfig.KIND_OPENVPN, parts[1] + ":" + parts[2]);
                }
                if (parts.length == 2) {
                    return new Parsed(VpnConfig.KIND_OPENVPN, parts[1] + ":1194");
                }
            }
        }
        throw new IllegalArgumentException(
                "invalid OpenVPN config: a 'remote <host> <port>' directive is required");
    }

    private static boolean containsRemoteDirective(String body) {
        for (String raw : body.split("\\R")) {
            if (stripComment(raw).trim().toLowerCase().startsWith("remote ")) return true;
        }
        return false;
    }

    /** Drop a trailing `# comment` / `; comment` (OpenVPN uses both). */
    private static String stripComment(String line) {
        int hash = line.indexOf('#');
        int semi = line.indexOf(';');
        int cut = -1;
        if (hash >= 0) cut = hash;
        if (semi >= 0 && (cut < 0 || semi < cut)) cut = semi;
        return cut >= 0 ? line.substring(0, cut) : line;
    }

    /** Split a `Key = Value` line into [key, value]; null if it is not a key/value line. */
    private static String[] splitKv(String line) {
        int eq = line.indexOf('=');
        if (eq <= 0) return null;
        return new String[]{line.substring(0, eq).trim(), line.substring(eq + 1).trim()};
    }
}
