package net.hugmesh.adminbff.domainregistry;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The write-time rules for {@code domain_registry.brand_title} and {@code headscale_url}
 * (operator decision 87e = A, hugmesh-admin-bff-api#100).
 *
 * <h3>Why these rules, and why here</h3>
 * Both values end up in hugmesh-generator {@code generate-brand-repos.sh}, which REFUSES to
 * render a brand whose {@code BRAND_TITLE} or {@code HEADSCALE_URL} breaks its rules
 * ({@code generate-brand-repos.sh:113-138} on origin/main 06bd65c5). If the admin-bff accepted
 * a value the renderer refuses, the SUPERADMIN would get a 200 here and the failure would only
 * surface much later, as a quarantined brand tree on a node. So the renderer's rules are copied
 * verbatim and enforced at the writer with a 400:
 * <ul>
 *   <li>{@code BRAND_TITLE}: non-empty, at most {@value #MAX_TITLE} characters, single-line, and
 *       none of {@code " \ $ ` | &} (they break a sed replacement or a shell assignment) nor
 *       {@code { }} (a second-order template-token injection primitive). Control characters are
 *       refused too; the renderer only names CR and LF, but no title needs a control
 *       character.</li>
 *   <li>{@code HEADSCALE_URL}: {@code ^https?://[A-Za-z0-9._~:/?#@!$()*,=%+-]+$}, exactly the
 *       renderer's {@code _RE_URL}, capped at the column width {@value #MAX_URL}.</li>
 * </ul>
 *
 * <p>{@code null} on either field means "not set": the node agent then keeps its documented
 * derivation (title = brand, headscale = {@code https://headscale.<clusterDomain>}).
 */
public final class DomainBrandFields {

    /** {@code generate-brand-repos.sh}: {@code [[ "${#BRAND_TITLE}" -le 128 ]]}; column width. */
    public static final int MAX_TITLE = 128;

    /** Column width of {@code headscale_url} (Liquibase 380). */
    public static final int MAX_URL = 512;

    /** {@code generate-brand-repos.sh} {@code _RE_URL}, verbatim. */
    private static final Pattern HEADSCALE_URL =
            Pattern.compile("^https?://[A-Za-z0-9._~:/?#@!$()*,=%+-]+$");

    /** The renderer's two forbidden-character sets, merged. */
    private static final String FORBIDDEN_TITLE_CHARS = "\"\\$`|&{}";

    private DomainBrandFields() {
    }

    /** Why {@code title} cannot be stored as a brand title, or empty when it can. */
    public static Optional<String> titleRefusal(String title) {
        if (title == null || title.isEmpty()) {
            return Optional.of("brandTitle must not be empty");
        }
        if (title.length() > MAX_TITLE) {
            return Optional.of("brandTitle is too long (" + title.length() + " > " + MAX_TITLE + ")");
        }
        for (int i = 0; i < title.length(); i++) {
            char c = title.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                return Optional.of("brandTitle must be a single printable line (no control characters)");
            }
            if (FORBIDDEN_TITLE_CHARS.indexOf(c) >= 0) {
                return Optional.of("brandTitle must not contain any of \" \\ $ ` | & { } — "
                        + "generate-brand-repos.sh refuses them (they break its sed/shell render "
                        + "or smuggle a template token)");
            }
        }
        return Optional.empty();
    }

    /** Why {@code url} cannot be stored as a headscale URL, or empty when it can. */
    public static Optional<String> headscaleUrlRefusal(String url) {
        if (url == null || url.isEmpty()) {
            return Optional.of("headscaleUrl must not be empty");
        }
        if (url.length() > MAX_URL) {
            return Optional.of("headscaleUrl is too long (" + url.length() + " > " + MAX_URL + ")");
        }
        if (!HEADSCALE_URL.matcher(url).matches()) {
            return Optional.of("headscaleUrl must be an http(s) URL with no whitespace, quotes, "
                    + "backticks, '|' or '&' (generate-brand-repos.sh _RE_URL): got '" + url + "'");
        }
        return Optional.empty();
    }
}
