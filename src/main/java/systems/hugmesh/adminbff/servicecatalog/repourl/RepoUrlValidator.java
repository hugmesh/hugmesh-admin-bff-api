package systems.hugmesh.adminbff.servicecatalog.repourl;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * STRUCTURAL validator for App-Store service-catalog {@code repoUrl} values — the
 * load-bearing SSRF / supply-chain guard for the descriptor/GitOps repo a SUPERADMIN points
 * the in-cluster Kaniko builder and ArgoCD at.
 *
 * <h3>Why a structural validator, not just a charset {@code @Pattern}</h3>
 * The DTO carries a charset {@code @Pattern} (PR #174) which kills the YAML/Job-spec injection
 * vector (no quotes/newlines/control chars survive into the Kaniko Job manifest). But a charset
 * allowlist is BLIND to URL <em>structure</em>: {@code file:///etc/passwd},
 * {@code http://169.254.169.254/latest/meta-data/} (cloud-metadata SSRF) and {@code git://}
 * (no host) all consist entirely of allowed characters and slip through. This validator parses
 * the URL and enforces three structural invariants the charset check cannot:
 * <ol>
 *   <li>SCHEME ∈ a small allowlist {@code {https, git, ssh}} — rejecting {@code file:} (local
 *       file read), plaintext {@code http:} (downgrade + most metadata-endpoint SSRF),
 *       {@code gopher:}/{@code dict:}/{@code javascript:} and every other scheme;</li>
 *   <li>a NON-EMPTY host — rejecting hostless URLs like {@code git://} or {@code https:///x};</li>
 *   <li>(optional, configurable) a HOST allowlist — when {@code app.appstore.repo-host-allowlist}
 *       is set, the host MUST match one of its entries; when unset/empty the host is unconstrained
 *       (behaviour unchanged from before this validator beyond the scheme/host guards).</li>
 * </ol>
 *
 * <p>It ALSO re-asserts the no-control-char / no-whitespace / length-≤512 invariants so it is a
 * complete, self-contained check usable as a DEFENCE-IN-DEPTH backstop at the sink
 * ({@code KanikoBuildLauncher}) where the DTO {@code @Pattern} layer can be bypassed by an
 * internal (non-controller) caller.
 *
 * <h3>Fail-closed, allocation-light, side-effect free</h3>
 * Every method is pure: it never logs the URL, never dials anything, and returns a typed
 * {@link Result} (or throws {@link IllegalArgumentException} via {@link #requireValid}). It is
 * safe to call from both the bean-validation path (controller {@code @Valid}) and the reactive
 * build path.
 */
public final class RepoUrlValidator {

    /** Max length mirrors the DTO {@code @Size(max = 512)} so the sink backstop agrees. */
    public static final int MAX_LENGTH = 512;

    /**
     * The accepted URL schemes (lowercase). {@code https} = TLS git/HTTP transport,
     * {@code git} = the git native protocol, {@code ssh} = git-over-SSH. Deliberately EXCLUDES
     * {@code file} (local read), plaintext {@code http} (downgrade + metadata SSRF) and every
     * exotic scheme. Kept package-visible for the constraint-message and tests.
     */
    static final Set<String> ALLOWED_SCHEMES = Set.of("https", "git", "ssh");

    private RepoUrlValidator() {
    }

    /**
     * The outcome of a validation: {@link #valid()} plus, when invalid, a stable
     * machine-readable {@link #reason()} (also the human message). A valid result carries a
     * {@code null} reason.
     */
    public record Result(boolean valid, String reason) {
        private static final Result OK = new Result(true, null);

        static Result ok() {
            return OK;
        }

        static Result fail(String reason) {
            return new Result(false, reason);
        }
    }

    /**
     * Validate {@code repoUrl} with NO host allowlist (any well-formed, allowed-scheme,
     * non-empty-host URL is accepted). Convenience for callers that do not configure a host
     * allowlist.
     */
    public static Result validate(String repoUrl) {
        return validate(repoUrl, Collections.emptySet());
    }

    /**
     * Validate {@code repoUrl} against the structural invariants and (when non-empty) the
     * {@code hostAllowlist}. Returns a typed {@link Result}; never throws for a hostile input.
     *
     * @param repoUrl       the candidate repository URL (may be null/blank)
     * @param hostAllowlist optional host allowlist; {@code null}/empty = host unconstrained,
     *                      otherwise the URL host (lowercased) MUST be a member
     */
    public static Result validate(String repoUrl, Set<String> hostAllowlist) {
        // 1. Presence + length.
        if (repoUrl == null || repoUrl.isBlank()) {
            return Result.fail("repoUrl is required");
        }
        if (repoUrl.length() > MAX_LENGTH) {
            return Result.fail("repoUrl is too long (max " + MAX_LENGTH + ")");
        }

        // 2. No ASCII control chars / whitespace / CR / LF anywhere. This is the YAML/Job-spec
        //    injection guard re-asserted at the structural layer: a newline or quote could break
        //    out of the Kaniko Job arg scalar. We reject ANY whitespace (incl. space) and ANY
        //    ISO control char outright — a legitimate repo URL never contains either.
        for (int i = 0; i < repoUrl.length(); i++) {
            char c = repoUrl.charAt(i);
            if (Character.isWhitespace(c) || Character.isISOControl(c)) {
                return Result.fail("repoUrl contains an illegal whitespace or control character");
            }
        }

        // 3. Parse as a structural URI. A malformed URI (e.g. stray ':' / '[') is rejected.
        final URI uri;
        try {
            uri = new URI(repoUrl);
        } catch (URISyntaxException e) {
            return Result.fail("repoUrl is not a well-formed URI");
        }

        // 4. Scheme allowlist — case-insensitive, must be one of {https, git, ssh}. A null scheme
        //    (a relative/opaque reference like "host/path") is rejected: we require an absolute,
        //    schemed URL so the transport is explicit and cannot default to something unsafe.
        final String scheme = uri.getScheme();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
            return Result.fail("repoUrl scheme must be one of " + ALLOWED_SCHEMES
                    + " (got '" + scheme + "')");
        }

        // 5. Non-empty host. URI#getHost returns null for a malformed / IPv6-bracket-broken /
        //    hostless authority; fall back to the raw authority's host segment so we still reject
        //    a missing host rather than accidentally accepting it.
        final String host = uri.getHost();
        if (host == null || host.isBlank()) {
            return Result.fail("repoUrl must have a non-empty host");
        }

        // 6. Optional host allowlist. When configured (non-empty) the host MUST match a member
        //    (case-insensitive). When unset/empty the host is unconstrained.
        if (hostAllowlist != null && !hostAllowlist.isEmpty()) {
            final String hostLower = host.toLowerCase(Locale.ROOT);
            final boolean allowed = hostAllowlist.stream()
                    .filter(h -> h != null && !h.isBlank())
                    .map(h -> h.trim().toLowerCase(Locale.ROOT))
                    .anyMatch(hostLower::equals);
            if (!allowed) {
                return Result.fail("repoUrl host '" + host + "' is not on the configured allowlist");
            }
        }

        return Result.ok();
    }

    /**
     * DEFENCE-IN-DEPTH entry point for the sink: validate and THROW
     * {@link IllegalArgumentException} (fail-closed) if invalid. Used by
     * {@code KanikoBuildLauncher} before it composes the value into the Kaniko Job context so an
     * internal caller that bypassed the DTO {@code @Valid} path still cannot reach the
     * template-substitution / {@code jobs().load()} sink with an unvalidated URL.
     *
     * @throws IllegalArgumentException if {@code repoUrl} fails any structural invariant
     */
    public static void requireValid(String repoUrl, Set<String> hostAllowlist) {
        Result r = validate(repoUrl, hostAllowlist);
        if (!r.valid()) {
            throw new IllegalArgumentException("invalid repoUrl: " + r.reason());
        }
    }

    /** Convenience {@link #requireValid(String, Set)} with no host allowlist. */
    public static void requireValid(String repoUrl) {
        requireValid(repoUrl, Collections.emptySet());
    }

    /**
     * Normalise a comma-separated host-allowlist config value (the
     * {@code app.appstore.repo-host-allowlist} property) into a trimmed, lowercased,
     * blank-free, insertion-ordered set. {@code null}/blank input → an empty set (unconstrained).
     */
    public static Set<String> parseHostAllowlist(String csv) {
        Set<String> out = new LinkedHashSet<>();
        if (csv == null || csv.isBlank()) {
            return out;
        }
        for (String token : csv.split(",")) {
            String t = token.trim().toLowerCase(Locale.ROOT);
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }
}
