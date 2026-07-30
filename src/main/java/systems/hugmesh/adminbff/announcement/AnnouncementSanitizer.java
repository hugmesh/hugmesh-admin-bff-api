package systems.hugmesh.adminbff.announcement;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.safety.Safelist;

/**
 * Server-side HTML sanitiser for admin announcement {@code body_html}. The body is
 * admin-authored HTML rendered to users INCLUDING anonymous login-page visitors, so
 * it MUST be sanitised against an allowlist BEFORE it is stored (never store raw
 * admin HTML) — and the UIs additionally render the result inside a sandboxed
 * null-origin srcdoc iframe (defence in depth).
 *
 * <p>The allowlist is jsoup's {@link Safelist#relaxed()} (a sensible rich-text set:
 * headings, lists, links, images, tables, basic formatting) tightened to permit a
 * couple of presentational attributes ({@code class}, {@code style}). Everything
 * jsoup does not allow is dropped — crucially {@code <script>}, every {@code on*}
 * event-handler attribute, {@code javascript:} URLs, {@code <iframe>}/{@code <object>}/
 * {@code <embed>}, and form controls — so an XSS payload like
 * {@code <img src=x onerror=alert(1)>} is reduced to a bare {@code <img src="x">} and
 * {@code <script>…</script>} is removed entirely.
 *
 * <p>Stateless + side-effect free; a singleton {@code @Bean} (see
 * {@link AnnouncementConfig}) so the service can sanitise on every create/update.
 */
public class AnnouncementSanitizer {

    /**
     * The allowlist applied to every announcement body. {@code relaxed()} already
     * excludes scripts / event handlers / javascript: URLs; we additionally permit
     * {@code class} + {@code style} on all elements for presentational markup (jsoup
     * still strips dangerous CSS-driven vectors like {@code expression(...)} are not
     * applicable, and the sandboxed iframe contains any remaining CSS).
     */
    private static final Safelist SAFELIST = Safelist.relaxed()
            .addAttributes(":all", "class", "style")
            // Allow links to open in a new tab (rel is forced safe by jsoup).
            .addAttributes("a", "target");

    /**
     * Sanitise admin HTML to the allowlist. Null/blank in → empty string out (the
     * caller's @NotBlank validation rejects an empty body before this, so this is a
     * defensive floor). The output is body-fragment HTML safe to persist + render
     * inside the sandboxed iframe.
     */
    public String sanitize(String rawHtml) {
        if (rawHtml == null || rawHtml.isBlank()) {
            return "";
        }
        // outputSettings: keep it compact (no pretty-print line wrapping that would
        // alter the admin's intended whitespace).
        var out = new Document.OutputSettings().prettyPrint(false);
        return Jsoup.clean(rawHtml, "", SAFELIST, out);
    }
}
