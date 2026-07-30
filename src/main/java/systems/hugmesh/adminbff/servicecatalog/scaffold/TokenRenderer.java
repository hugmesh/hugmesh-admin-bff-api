package systems.hugmesh.adminbff.servicecatalog.scaffold;

import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The LITERAL {@code {{TOKEN}}} renderer for the vendored scaffold skeletons. The generator
 * authors its skeletons as Handlebars templates, but the scaffold surface only substitutes a
 * small, fixed set of {@code {{UPPER_SNAKE}}} identity tokens — so a full Handlebars engine
 * would be overkill (and a supply-chain surface). This renderer does exactly two things:
 *
 * <ol>
 *   <li>replaces each {@code {{KEY}}} whose {@code KEY} is present in the render context with
 *       its value (a plain literal {@link String#replace} — no regex, no partials);</li>
 *   <li>strips {@code {{!}}} (the Handlebars empty-comment the skeletons use as a token
 *       SEPARATOR so a {@code ...{{CLUSTER_DOMAIN}}{{!}}}} sequence's closing {@code }} of the
 *       token is not glued to a following literal {@code }} into a triple-stache).</li>
 * </ol>
 *
 * <h3>Hard-fail on residual (no silently-broken scaffolds)</h3>
 * After rendering, {@link #render} scans for any {@code {{UPPER_SNAKE}}} token still present and
 * THROWS {@link UnrenderedTokenException} listing them. A skeleton that grows a new token the
 * context does not carry therefore FAILS the archive render loudly instead of shipping a broken
 * starter with a literal {@code {{NEW_TOKEN}}} in it — the platform's no-half-done law. The
 * render tests exercise this on every archetype.
 */
public final class TokenRenderer {

    /** The Handlebars empty-comment separator the skeletons use; renders to nothing. */
    private static final String COMMENT = "{{!}}";

    /** A residual UPPER_SNAKE token: {@code {{ABC_DEF}}}. Anchors the hard-fail scan. */
    private static final Pattern RESIDUAL = Pattern.compile("\\{\\{([A-Z][A-Z0-9_]*)}}");

    private TokenRenderer() {
    }

    /**
     * Render {@code content}: substitute every {@code {{KEY}}} present in {@code context}, strip
     * the {@code {{!}}} separators, then HARD-FAIL if any {@code {{UPPER_SNAKE}}} token survives.
     *
     * @param content the raw skeleton file text
     * @param context the render tokens (KEY -&gt; value); values are substituted literally
     * @return the rendered text (no {@code {{...}}} tokens remain)
     * @throws UnrenderedTokenException if any {@code {{UPPER_SNAKE}}} token is unresolved
     */
    public static String render(String content, Map<String, String> context) {
        if (content == null || content.isEmpty()) {
            return content == null ? "" : content;
        }
        String out = content;
        for (Map.Entry<String, String> e : context.entrySet()) {
            String value = e.getValue() == null ? "" : e.getValue();
            out = out.replace("{{" + e.getKey() + "}}", value);
        }
        out = out.replace(COMMENT, "");
        List<String> residual = residualTokens(out);
        if (!residual.isEmpty()) {
            throw new UnrenderedTokenException(residual);
        }
        return out;
    }

    /** The sorted, de-duplicated list of {@code {{UPPER_SNAKE}}} tokens still present in
     *  {@code rendered} (empty when fully rendered). Package-visible for the render tests. */
    static List<String> residualTokens(String rendered) {
        TreeSet<String> found = new TreeSet<>();
        Matcher m = RESIDUAL.matcher(rendered);
        while (m.find()) {
            found.add("{{" + m.group(1) + "}}");
        }
        return List.copyOf(found);
    }

    /** Thrown when a rendered skeleton file still carries an unresolved {@code {{UPPER_SNAKE}}}
     *  token — the render context is missing a mapping the skeleton needs. Mapped to a 500 by
     *  the archive endpoint (a server-side catalog defect, never a client fault). */
    public static class UnrenderedTokenException extends RuntimeException {
        private final transient List<String> tokens;

        public UnrenderedTokenException(List<String> tokens) {
            super("scaffold skeleton has unrendered tokens: " + tokens);
            this.tokens = tokens;
        }

        /** The unresolved tokens (e.g. {@code [{{NEW_TOKEN}}]}). */
        public List<String> tokens() {
            return tokens;
        }
    }
}
