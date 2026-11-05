package net.hugmesh.adminbff.meshtoken;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The signed body of a HugMesh token v1, and the ONE serializer that turns it into the bytes
 * that get signed.
 *
 * <h2>The contract this mirrors</h2>
 * The format is owned by the Studio's reference implementation
 * ({@code hugmesh-generator studio/hugmesh_studio/core/mesh_token.py}, spec
 * {@code docs/HUGMESH-TOKEN.md}). The tray re-serialises a payload with
 * {@code json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)} and
 * REFUSES one whose bytes differ, so this class must produce exactly those bytes:
 * <ul>
 *   <li>all twelve keys, always, in sorted order ({@link #KEYS});</li>
 *   <li>no whitespace; integers as plain decimals; {@code true}/{@code false};</li>
 *   <li>strings escaped the way {@code ensure_ascii} escapes them ({@link #appendJsonString}).</li>
 * </ul>
 * It is hand-written rather than Jackson because Jackson's key order, number and escape rules
 * are configuration that can drift; these twelve lines cannot.
 *
 * <h2>Validation at the boundary</h2>
 * {@link #check(long)} applies the rules of the Python {@code check_fields} (the tray runs the
 * same checks again on import), plus two stricter ones of our own: every string is printable
 * ASCII without {@code "} or {@code \}, and {@code node_name} is a DNS label. With those in
 * force no string ever needs escaping; the escaper is still exact for the day a rule loosens.
 */
public record MeshTokenPayload(
        String authKey,
        String domain,
        long expires,
        String id,
        long issued,
        String issuer,
        String loginServer,
        String mesh,
        String nodeName,
        String role,
        boolean shell) {

    /** The {@code format} field's only value, and the token's first dot-separated part. */
    public static final String FORMAT = "hugmesh-token-v1";

    /** The JSON keys, in the order {@code sort_keys=True} emits them. */
    public static final List<String> KEYS = List.of(
            "auth_key", "domain", "expires", "format", "id", "issued", "issuer",
            "login_server", "mesh", "node_name", "role", "shell");

    /** The four person tiers ({@code PERSON_ROLE_CHOICES} in the Studio). */
    public static final List<String> ROLES = List.of("user", "mod", "admin", "superadmin");

    /** The roles that may hold shell access ({@code SHELL_ROLES}). */
    public static final List<String> SHELL_ROLES = List.of("admin", "superadmin");

    /** The longest a token may live ({@code MAX_LIFETIME_S}, 90 days). */
    public static final long MAX_LIFETIME_SECONDS = 90L * 24 * 3600;

    /** No real token was issued before 2020-01-01 UTC ({@code _EARLIEST}). */
    public static final long EARLIEST = 1_577_836_800L;

    static final Pattern MESH_RE = Pattern.compile("^[a-z0-9][a-z0-9-]{0,62}$");
    static final Pattern DOMAIN_RE = Pattern.compile(
            "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$");
    static final Pattern ISSUER_RE = Pattern.compile("^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$");
    static final Pattern LOGIN_SERVER_RE = Pattern.compile("^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$");
    /** Stricter than the tray (which only needs SOME label out of it): a DNS label, or empty. */
    static final Pattern NODE_NAME_RE = Pattern.compile("^[a-z0-9][a-z0-9-]{0,62}$");
    static final Pattern ID_RE = Pattern.compile("^[0-9a-f]{16}$");

    // ── canonical bytes ─────────────────────────────────────────────────────────────

    /** The exact bytes that are signed and base64url-encoded into the token. */
    public byte[] canonicalBytes() {
        StringBuilder b = new StringBuilder(512);
        b.append('{');
        key(b, "auth_key", true).append(str(authKey));
        key(b, "domain", false).append(str(domain));
        key(b, "expires", false).append(expires);
        key(b, "format", false).append(str(FORMAT));
        key(b, "id", false).append(str(id));
        key(b, "issued", false).append(issued);
        key(b, "issuer", false).append(str(issuer));
        key(b, "login_server", false).append(str(loginServer));
        key(b, "mesh", false).append(str(mesh));
        key(b, "node_name", false).append(str(nodeName));
        key(b, "role", false).append(str(role));
        key(b, "shell", false).append(shell ? "true" : "false");
        b.append('}');
        return b.toString().getBytes(StandardCharsets.US_ASCII);
    }

    private static StringBuilder key(StringBuilder b, String k, boolean first) {
        if (!first) {
            b.append(',');
        }
        appendJsonString(b, k);
        return b.append(':');
    }

    private static String str(String s) {
        StringBuilder b = new StringBuilder();
        appendJsonString(b, s == null ? "" : s);
        return b.toString();
    }

    /**
     * Append {@code s} as a JSON string exactly as Python's {@code json.dumps(...,
     * ensure_ascii=True)} writes it: {@code "} and {@code \} backslash-escaped, the five short
     * escapes {@code \n \r \t \b \f}, and every other char outside {@code 0x20..0x7E} (0x7F
     * included) as a lowercase {@code &#92;u00xx}. Java strings are UTF-16, so a character outside
     * the BMP is already the surrogate pair Python emits.
     */
    static void appendJsonString(StringBuilder b, String s) {
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                default -> {
                    if (c >= 0x20 && c <= 0x7E) {
                        b.append(c);
                    } else {
                        b.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    }
                }
            }
        }
        b.append('"');
    }

    // ── validation ──────────────────────────────────────────────────────────────────

    /** Thrown for a payload this BFF must not sign; the message is a sentence for the operator. */
    public static final class InvalidPayloadException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        public InvalidPayloadException(String message) {
            super(message);
        }
    }

    /**
     * Refuse (with {@link InvalidPayloadException}) unless every field is one the tray will act
     * on. Mirrors {@code mesh_token.check_fields}; {@code nowEpochSeconds} plays its {@code now}.
     */
    public void check(long nowEpochSeconds) {
        for (String k : KEYS) {
            String v = stringField(k);
            if (v != null && !safeAscii(v)) {
                throw new InvalidPayloadException("The token field " + k
                        + " must be printable ASCII without quotes or backslashes.");
            }
        }
        if (mesh == null || !MESH_RE.matcher(mesh).matches()) {
            throw new InvalidPayloadException("The mesh name is not a valid name "
                    + "(lower-case letters, digits and '-', at most 63).");
        }
        if (domain == null || !DOMAIN_RE.matcher(domain).matches()) {
            throw new InvalidPayloadException("The access domain is not a lower-case domain name "
                    + "with at least two labels.");
        }
        if (!ROLES.contains(role)) {
            throw new InvalidPayloadException("The role must be one of " + String.join(", ", ROLES) + ".");
        }
        if (shell && !SHELL_ROLES.contains(role)) {
            throw new InvalidPayloadException("Shell access can only be granted to admin or superadmin.");
        }
        if (loginServer == null || !LOGIN_SERVER_RE.matcher(loginServer).matches()) {
            throw new InvalidPayloadException("The login server must be https://host[:port] and nothing else.");
        }
        String host = loginServerHost(loginServer);
        if (!host.equals(domain) && !host.endsWith("." + domain)) {
            throw new InvalidPayloadException("The login server " + host
                    + " is outside the access domain " + domain + ".");
        }
        if (authKey == null || authKey.isEmpty() || authKey.chars().anyMatch(Character::isWhitespace)) {
            throw new InvalidPayloadException("The pre-auth key is empty or contains whitespace.");
        }
        if (issuer == null || !ISSUER_RE.matcher(issuer).matches()) {
            throw new InvalidPayloadException("The issuer is not an ssh-ed25519 public key.");
        }
        if (issued < EARLIEST) {
            throw new InvalidPayloadException("The issue time is before 2020.");
        }
        if (expires <= issued || expires - issued > MAX_LIFETIME_SECONDS) {
            throw new InvalidPayloadException("The lifetime must be between a moment and 90 days.");
        }
        if (issued > nowEpochSeconds + 300) {
            throw new InvalidPayloadException("The issue time is in the future.");
        }
        if (nowEpochSeconds >= expires) {
            throw new InvalidPayloadException("The token would already have expired.");
        }
        if (nodeName == null || (!nodeName.isEmpty() && !NODE_NAME_RE.matcher(nodeName).matches())) {
            throw new InvalidPayloadException("The node name must be empty or a DNS label "
                    + "(lower-case letters, digits and '-', at most 63).");
        }
        if (id == null || (!id.isEmpty() && !ID_RE.matcher(id).matches())) {
            throw new InvalidPayloadException("The token id must be empty or 16 hex characters.");
        }
    }

    private String stringField(String k) {
        return switch (k) {
            case "auth_key" -> authKey;
            case "domain" -> domain;
            case "id" -> id;
            case "issuer" -> issuer;
            case "login_server" -> loginServer;
            case "mesh" -> mesh;
            case "node_name" -> nodeName;
            case "role" -> role;
            default -> null;
        };
    }

    /** Printable ASCII (0x20..0x7E) without {@code "} or {@code \}: never needs a JSON escape. */
    static boolean safeAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c > 0x7E || c == '"' || c == '\\') {
                return false;
            }
        }
        return true;
    }

    /** The lower-cased host of an {@code https://host[:port][/]} URL already matched by the regex. */
    static String loginServerHost(String loginServer) {
        String rest = loginServer.substring("https://".length());
        int cut = rest.length();
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == ':' || c == '/') {
                cut = i;
                break;
            }
        }
        return rest.substring(0, cut).toLowerCase(Locale.ROOT);
    }

    /** Never print the pre-auth key. */
    @Override
    public String toString() {
        return "MeshTokenPayload[id=" + id + ", mesh=" + mesh + ", domain=" + domain + ", role=" + role
                + ", shell=" + shell + ", loginServer=" + loginServer + ", issued=" + issued
                + ", expires=" + expires + ", nodeName=" + nodeName + ", authKey=<redacted>]";
    }
}
