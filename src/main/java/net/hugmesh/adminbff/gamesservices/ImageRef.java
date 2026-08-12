package net.hugmesh.adminbff.gamesservices;

import java.util.regex.Pattern;

/**
 * The SERVER-SIDE digest-pin validator for games-catalog image references. Arbitrary
 * container exec is the core risk of an app-store of game servers, so the catalog only
 * ever accepts a DIGEST-PINNED image ({@code repo@sha256:<64hex>}) — a mutable tag
 * (e.g. {@code repo:latest}) could be re-pointed at a malicious image AFTER a superadmin
 * curated/tested it, so tag-only references are REJECTED here (and by a defence-in-depth
 * DB CHECK {@code image_ref LIKE '%@sha256:%'} in changelog 090).
 *
 * <p>A valid reference is {@code <name>@sha256:<64 lowercase hex>} where {@code <name>}
 * is a non-empty registry/repository path (host[:port]/path segments). This is a
 * deliberately strict subset of the OCI reference grammar — enough to bind a specific
 * immutable image, not a full reference parser.
 */
public final class ImageRef {

    private ImageRef() {}

    /** {@code name@sha256:<64 lowercase hex>} — the only shape the catalog accepts. */
    private static final Pattern DIGEST_PINNED = Pattern.compile(
            "^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$");

    /** True iff {@code imageRef} is a well-formed digest-pinned reference. */
    public static boolean isDigestPinned(String imageRef) {
        return imageRef != null && DIGEST_PINNED.matcher(imageRef).matches();
    }

    /**
     * Returns the reference unchanged if it is digest-pinned, otherwise throws so the
     * caller surfaces a 400. The message names the requirement (digest-pin) without
     * echoing a potentially attacker-influenced full ref verbatim beyond a short prefix.
     */
    public static String validate(String imageRef) {
        if (!isDigestPinned(imageRef)) {
            throw new IllegalArgumentException(
                    "imageRef must be digest-pinned (repo@sha256:<64 hex>); tag-only "
                    + "references are rejected (arbitrary-container exec containment)");
        }
        return imageRef;
    }
}
