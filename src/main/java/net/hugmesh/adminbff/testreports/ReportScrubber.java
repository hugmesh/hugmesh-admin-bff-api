package net.hugmesh.adminbff.testreports;

import java.util.regex.Pattern;

/**
 * Read-time secret scrubber applied to every text artifact streamed out of the
 * Test-Reports download (defence-in-depth: the test-runner ALSO scrubs at
 * write-time, but a download must NEVER trust that the stored bytes are clean —
 * the design requires "secrets scrubbed" + "re-sanitize on read").
 *
 * <p>Redacts the high-signal secret shapes that leak into test logs / JUnit output:
 * Bearer/JWT tokens, Casdoor client secrets, Authorization headers, k8s Secret
 * data, connection-string passwords, and the swarm test password. Each match is
 * replaced with a fixed {@code ***REDACTED***} marker so the report stays
 * human-readable (line structure preserved) but carries no live credential.
 *
 * <p>This is intentionally conservative + allowlist-of-shapes (over-redact rather
 * than under-redact); it is NOT a parser. Binary artifacts (e.g. screenshots) are
 * passed through untouched by the archive (only text entries are scrubbed).
 */
public final class ReportScrubber {

    private record Rule(Pattern pattern, String replacement) {}

    private static final String R = "***REDACTED***";

    private static final Rule[] RULES = new Rule[]{
            // JWTs: header.payload.signature (base64url triplets).
            new Rule(Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}"), R),
            // Bearer tokens (Authorization: Bearer <tok> or "Bearer <tok>").
            new Rule(Pattern.compile("(?i)(bearer\\s+)[A-Za-z0-9._-]{8,}"), "$1" + R),
            // Authorization / Proxy-Authorization header values (Basic + anything).
            new Rule(Pattern.compile("(?i)(authorization\\s*[:=]\\s*)\\S+"), "$1" + R),
            // key=value / "key": "value" for secret-ish keys (password, secret,
            // token, client_secret, apikey, api_key, pwd, passwd).
            new Rule(Pattern.compile(
                    "(?i)(\"?(?:password|passwd|pwd|secret|client_secret|clientsecret|token|api[_-]?key)\"?\\s*[:=]\\s*\"?)"
                    + "[^\"\\s,}]+"), "$1" + R),
            // Connection-string passwords: scheme://user:PASSWORD@host
            new Rule(Pattern.compile("(://[^:/@\\s]+:)[^@/\\s]+(@)"), "$1" + R + "$2"),
            // The deterministic swarm test password env, if it ever lands in a log.
            new Rule(Pattern.compile("(?i)(E2E_SWARM_PASSWORD\\s*[:=]\\s*)\\S+"), "$1" + R),
    };

    private ReportScrubber() {
    }

    /** Scrub a single text artifact. Null-safe; preserves line structure. */
    public static String scrub(String text) {
        if (text == null || text.isEmpty()) return text;
        String out = text;
        for (Rule rule : RULES) {
            out = rule.pattern().matcher(out).replaceAll(rule.replacement());
        }
        return out;
    }

    /** True if the entry name looks like a text artifact we should scrub (vs binary
     *  like a screenshot/trace that is passed through). */
    public static boolean isText(String entryName) {
        if (entryName == null) return false;
        String n = entryName.toLowerCase();
        return n.endsWith(".xml") || n.endsWith(".json") || n.endsWith(".txt")
                || n.endsWith(".log") || n.endsWith(".md") || n.endsWith(".csv")
                || n.endsWith(".html") || n.endsWith(".yaml") || n.endsWith(".yml");
    }
}
