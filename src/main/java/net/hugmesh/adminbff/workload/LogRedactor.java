package net.hugmesh.adminbff.workload;

import java.util.regex.Pattern;

/**
 * Server-side secret redaction applied to EVERY log line (both the SSE live-tail and the
 * non-stream read, and the Uptrace/ClickHouse history path) BEFORE it leaves the BFF. The
 * console must never relay a leaked secret to the UI, so a conservative allowlist of
 * common secret-bearing token shapes is masked. This is intentionally aggressive (it may
 * over-redact) — a false-positive masked token is acceptable, a leaked one is not.
 */
public final class LogRedactor {

    private LogRedactor() {
    }

    private static final Pattern[] PATTERNS = {
            // -----BEGIN ... PRIVATE KEY----- blocks (single-line occurrences)
            Pattern.compile("-----BEGIN[^-]+PRIVATE KEY-----[\\s\\S]*?-----END[^-]+PRIVATE KEY-----"),
            // JWT-ish three-part base64
            Pattern.compile("\\beyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\b"),
            // Authorization: Bearer/Basic header values (BEFORE the key=value rule so the
            // whole "Bearer <token>" / "Basic <token>" value is masked, not just the scheme).
            Pattern.compile("(?i)(Authorization\\s*[:=]\\s*)?(Bearer|Basic)\\s+[A-Za-z0-9._~+/=-]{8,}"),
            // key=value / key: value where the key looks secret-bearing — the value is the
            // REST of the token run (greedy to end-of-token), so a multi-token value is masked.
            Pattern.compile("(?i)\\b(password|passwd|pwd|secret|token|apikey|api_key|"
                    + "access[_-]?key|private[_-]?key|client[_-]?secret|authorization|auth|"
                    + "session|cookie)\\b\\s*[=:]\\s*\\S+"),
            // long base64-ish blobs (likely keys)
            Pattern.compile("\\b[A-Za-z0-9+/]{40,}={0,2}\\b"),
    };

    private static final String MASK = "***REDACTED***";

    /** Redact secret-bearing substrings from one log line. Null-safe (returns null). */
    public static String redact(String line) {
        if (line == null || line.isEmpty()) return line;
        String out = line;
        for (Pattern p : PATTERNS) {
            out = p.matcher(out).replaceAll(MASK);
        }
        return out;
    }
}
