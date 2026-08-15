package net.hugmesh.adminbff.theme;

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
 * {@code domain} empty ({@code PrincipalDomain.NO_DOMAIN}) is the MESH DEFAULT: the
 * theme a domain with no row of its own inherits.
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

    /** Normalise on the way in so a blank and a null cannot mean different things in
     *  the DB — the primary key is the domain, and "" vs null would allow two rows for
     *  the mesh default. */
    public DomainTheme {
        domain = domain == null ? "" : domain.trim();
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
