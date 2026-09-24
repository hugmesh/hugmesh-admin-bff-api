package net.hugmesh.adminbff.domainregistry;

import java.util.List;
import java.util.Optional;

/**
 * The {@code domain_registry.idp} vocabulary — operator DECISION 29b, 2026-09-17:
 * <em>"add the {@code idp} column to 012-domain-registry.xml rather than deriving it"</em>.
 *
 * <p>Which Casdoor serves a domain's sign-in:
 * <ul>
 *   <li>{@link #SUPERDOMAIN} &mdash; ride the mesh's one central Casdoor. The DEFAULT, matching
 *       the Studio {@code Domain} dataclass default
 *       ({@code studio/hugmesh_studio/core/config.py}: {@code idp: str = DOMAIN_IDP_SUPERDOMAIN})
 *       and the KEYS-manifest reading that an ABSENT {@code idp} means superdomain. A
 *       superdomain row provisions nothing per-domain.</li>
 *   <li>{@link #OWN} &mdash; the domain runs its OWN Casdoor instance (plus its own Postgres) in
 *       its {@code <slug>-pki} namespace. This is the generator selector gate: only
 *       {@code idp == "own"} rows ever become a per-domain Application.</li>
 * </ul>
 *
 * <p><b>Flipping it is not free.</b> {@code own -> superdomain} makes the domain's element fall
 * out of the generator's selector, which PRUNES its instance ({@code prune: true}); the
 * generator's own removal runbook ({@code docs/DOMAIN-IDP.md}) requires the domain's
 * {@code APP_TENANCY_ISSUERS}/{@code APP_TENANCY_HOSTS} registry pair to be retired FIRST, or a
 * live issuer maps to a pruned IdP. Nothing in this repo materialises elements yet, so the flip
 * is inert today; whoever builds that writer owns the ordering.
 *
 * <p>Pure and side-effect free; no Spring, no I/O.
 */
public final class DomainIdp {

    /** The domain runs its own per-domain Casdoor instance (the generator's selector value). */
    public static final String OWN = "own";

    /** The domain rides the mesh's central Casdoor. The default, and the DB column default. */
    public static final String SUPERDOMAIN = "superdomain";

    /** The closed vocabulary, matching the Studio's {@code DOMAIN_IDP_CHOICES} order. */
    public static final List<String> CHOICES = List.of(SUPERDOMAIN, OWN);

    private DomainIdp() {
    }

    /**
     * Normalise a request value: {@code null}/blank means the caller said nothing, which is the
     * {@link #SUPERDOMAIN} default (the same reading the Studio's {@code _domain_from_dict}
     * applies to an absent key, so a manifest and a registry row agree).
     */
    public static String normalize(String idp) {
        return idp == null || idp.isBlank() ? SUPERDOMAIN : idp.trim();
    }

    /** Why this value is not a legal {@code idp}, or empty when it is. */
    public static Optional<String> refusalReason(String idp) {
        String normalized = normalize(idp);
        if (!CHOICES.contains(normalized)) {
            return Optional.of("idp must be one of " + String.join("|", CHOICES)
                    + ": got '" + normalized + "'");
        }
        return Optional.empty();
    }

    /** Whether this domain runs its own per-domain IdP. */
    public static boolean isOwn(String idp) {
        return OWN.equals(normalize(idp));
    }
}
