package net.hugmesh.adminbff.theme;

import net.hugmesh.commons.security.PrincipalDomain;

/**
 * One domain's chosen theme.
 *
 * The SELECTION, not a rendered stylesheet. preset + ramp + style + decor are the four
 * orthogonal axes the Studio's theme module exposes (26+ presets x 8 time-of-day ramps
 * x 6 styles x 5 decors), and storing the choice rather than the CSS means a correction
 * to the colour maths reaches every domain without a data migration — which matters here
 * because that derivation has already been corrected twice (the --sd-/--hug- prefix
 * bug, and accent text falling below AA on the lighter ramps).
 *
 * <p>EVERY axis has to be here, not just the ones that pick colours. An axis the renderer
 * knows about and this record does not is worse than an unsupported axis: the stored
 * selection stops being able to reproduce the stored render, and {@link #sameSelection}
 * then declares a genuinely different theme unchanged. That is exactly how {@code decor}
 * behaved while it existed only in the Studio — a domain rendered with {@code uwu} kept
 * its decorated stylesheet through every subsequent save, with no control anywhere able to
 * turn it off.
 *
 * {@code domain} empty ({@link #MESH_DEFAULT}) is the MESH DEFAULT: the theme a domain
 * with no row of its own inherits.
 *
 * <p>{@link PrincipalDomain#NO_DOMAIN} is NOT the empty string — it is the sentinel
 * {@code " no-domain"}, whose leading space cannot equal a registry-sanitized domain.
 * Everything that keys a row therefore has to go through {@link #normalizeDomain} rather
 * than through {@code trim()}: trimming that sentinel yields the ordinary-looking string
 * {@code "no-domain"}, which is neither the mesh default nor a real domain, and letting
 * it reach the primary key is how a fail-closed principal ends up owning a row.
 */
public record DomainTheme(
        String domain,
        String preset,
        String ramp,
        String style,
        /* theme.DECOR_VARIANTS — decorative nav-link text (none|uwu|arrows|terminal|
         * sparkle). Cosmetic, but part of the selection all the same: it changes the
         * rendered sheet, so a cache keyed on the selection has to see it change. */
        String decor,
        String primaryHex,
        String secondaryHex,
        String updatedBy,
        /* The DERIVED stylesheet, pushed by the renderer -- never computed here. Null
         * means "not rendered yet", which serves empty CSS and therefore the shipped
         * default chrome. See changeset 340-4 for why this is a cache and not truth.
         *
         * NEVER SERIALISED. It is read server-side by the /bff/public/theme.css handler
         * and nothing else; a list of 38 domains would otherwise ship ~270 KB of
         * stylesheet to an admin screen that renders none of it. renderedBy stays
         * visible, because "which renderer produced this" is what makes a stale cache
         * identifiable. */
        @com.fasterxml.jackson.annotation.JsonIgnore
        String renderedCss,
        String renderedBy) {

    public static final String DEFAULT_RAMP = "dark";
    public static final String DEFAULT_STYLE = "soft";
    /** No decoration — {@code theme.DEFAULT_DECOR}. The default is OFF deliberately: the
     *  chrome this axis replaced appended ' UwU' to every nav link with no way to remove
     *  it, and pseudo-element {@code content} is read aloud by screen readers. */
    public static final String DEFAULT_DECOR = "none";

    /** The storage key for the MESH DEFAULT — the row every domain without one of its
     *  own inherits. Empty, because no real domain can be blank: {@code DomainRegistry}
     *  sanitizes names to {@code [a-z0-9-]} and collapses blanks. */
    public static final String MESH_DEFAULT = "";

    /**
     * The canonical storage key for a TARGET domain.
     *
     * <p>Null, blank, and {@link PrincipalDomain#NO_DOMAIN} all mean "no specific
     * domain", which as a target is the mesh default. Collapsing them here is what keeps
     * a write and a read agreeing on one key — the mesh default was previously WRITTEN
     * through the record (trimmed to {@code "no-domain"}) but READ back as the untrimmed
     * sentinel, so it never resolved and no domain ever inherited it.
     *
     * <p>Only ever apply this to a target. An ACTOR with no resolvable domain must match
     * NOTHING, not the mesh default — see {@code DomainThemeService.actingDomain}.
     */
    public static String normalizeDomain(String domain) {
        if (domain == null) {
            return MESH_DEFAULT;
        }
        String d = domain.trim();
        // Both spellings of the sentinel: as passed, and as an earlier trim would leave it.
        if (d.isEmpty() || d.equals(PrincipalDomain.NO_DOMAIN.trim())) {
            return MESH_DEFAULT;
        }
        return d;
    }

    /** Normalise on the way in so a blank, a null, and the NO_DOMAIN sentinel cannot mean
     *  three different things in the DB — the primary key is the domain, and any two
     *  spellings that mean "the default" would allow two rows for the mesh default. */
    public DomainTheme {
        domain = normalizeDomain(domain);
        preset = preset == null ? "" : preset.trim();
        ramp = (ramp == null || ramp.isBlank()) ? DEFAULT_RAMP : ramp.trim();
        style = (style == null || style.isBlank()) ? DEFAULT_STYLE : style.trim();
        // Blank collapses to "none" rather than to null: the column is NOT NULL, and more
        // to the point sameSelection has to compare an omitted decor against a stored one
        // without a null-vs-"none" distinction that means nothing to the renderer.
        decor = (decor == null || decor.isBlank()) ? DEFAULT_DECOR : decor.trim();
        primaryHex = blankToNull(primaryHex);
        secondaryHex = blankToNull(secondaryHex);
        renderedCss = blankToNull(renderedCss);
        renderedBy = blankToNull(renderedBy);
    }

    /** The SELECTION alone, carrying no render — what an admin write is. The cache is
     *  filled separately by whoever can actually derive it.
     *
     *  <p>{@code decor} is a required argument here rather than an overload that defaults
     *  it, because "the axis was left out of a call and quietly became its default" is the
     *  precise failure this constructor's shorter predecessor allowed. */
    public DomainTheme(String domain, String preset, String ramp, String style, String decor,
                       String primaryHex, String secondaryHex, String updatedBy) {
        this(domain, preset, ramp, style, decor, primaryHex, secondaryHex, updatedBy, null, null);
    }

    /** Does {@code other} choose the same THEME as this? Compares the SELECTION only,
     *  deliberately ignoring the render and the audit fields — it is the question "is the
     *  cached stylesheet still valid?", and {@code updatedBy} changing does not repaint
     *  anything.
     *
     *  <p>It must compare EVERY axis that reaches the stylesheet, including the merely
     *  decorative ones. Omitting {@code decor} here was not a cosmetic gap: a domain the
     *  Studio had rendered with {@code uwu} answered "same selection" to every later save
     *  of the same colours, so the decorated sheet survived writes that were meant to
     *  replace it and nothing in the product could turn the decoration off. An axis that
     *  changes the bytes has to be able to invalidate them. */
    public boolean sameSelection(DomainTheme other) {
        return other != null
                && preset.equals(other.preset())
                && ramp.equals(other.ramp())
                && style.equals(other.style())
                && decor.equals(other.decor())
                && java.util.Objects.equals(primaryHex, other.primaryHex())
                && java.util.Objects.equals(secondaryHex, other.secondaryHex());
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s.trim();
    }
}
