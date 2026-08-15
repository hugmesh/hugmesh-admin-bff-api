package net.hugmesh.adminbff.theme;

/**
 * What an ANONYMOUS surface is told about a domain's theme.
 *
 * <p>{@link DomainTheme} minus {@code updatedBy}. That field answers "who made everything
 * pink?", which is an admin-side audit question; serving it on the unauthenticated
 * endpoint would hand every visitor the identity of an administrator (the JWT subject —
 * in this deployment an email address) in exchange for nothing they need in order to
 * render the right colours.
 *
 * <p>A separate record rather than {@code @JsonIgnore} on the field, because the admin
 * surface legitimately DOES need {@code updatedBy}: ignoring it globally would blind the
 * audit view to make the public view safe. A projection makes the boundary explicit and
 * cannot be re-widened by a Jackson configuration change elsewhere.
 */
public record PublicTheme(
        String domain,
        String preset,
        String ramp,
        String style,
        /* Every selection axis crosses this boundary, decorative ones included: a surface
         * asking what theme applies to it must get an answer it could re-render from, and
         * an axis omitted here is one a caller cannot see it is subject to. */
        String decor,
        String primaryHex,
        String secondaryHex) {

    public static PublicTheme of(DomainTheme t) {
        return new PublicTheme(t.domain(), t.preset(), t.ramp(), t.style(), t.decor(),
                t.primaryHex(), t.secondaryHex());
    }
}
