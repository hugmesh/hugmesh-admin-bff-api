package net.hugmesh.adminbff.theme;

import net.hugmesh.commons.security.PrincipalDomain;

/**
 * One domain's chosen theme.
 *
 * The SELECTION, not a rendered stylesheet. preset + ramp + style are the three
 * orthogonal axes the Studio's theme module exposes (26+ presets x 8 time-of-day ramps
 * x 6 styles), and storing the choice rather than the CSS means a correction to the
 * colour maths reaches every domain without a data migration — which matters here
 * because that derivation has already been corrected twice (the --sd-/--hug- prefix
 * bug, and accent text falling below AA on the lighter ramps).
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
        String primaryHex,
        String secondaryHex,
        String updatedBy) {

    public static final String DEFAULT_RAMP = "dark";
    public static final String DEFAULT_STYLE = "soft";

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
        primaryHex = blankToNull(primaryHex);
        secondaryHex = blankToNull(secondaryHex);
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s.trim();
    }
}
