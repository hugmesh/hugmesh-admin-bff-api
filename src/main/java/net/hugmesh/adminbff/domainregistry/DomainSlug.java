package net.hugmesh.adminbff.domainregistry;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The domain SLUG rule — operator DECISION 29a, 2026-09-17: <em>"the slug rule is
 * {@code ns_prefix}; it also names the Vault path {@code secret/<slug>/casdoor}, so namespace
 * and secret path now agree, and a wrong slug mis-addresses a secret"</em>.
 *
 * <p>So one {@code domain_registry} column carries THREE identities at once:
 * <ul>
 *   <li>the ArgoCD Application name &mdash; {@code casdoor-<slug>};</li>
 *   <li>the tenant namespace &mdash; {@code <slug>-pki} (the ApplicationSet's kustomize
 *       namespace and sync destination, created with {@code CreateNamespace=true});</li>
 *   <li>the Vault KV path &mdash; {@code secret/<slug>/casdoor}, whose three ExternalSecrets
 *       carry the instance's DB password, admin password and OIDC client secret.</li>
 * </ul>
 *
 * <p>That third one is why this is a validator and not a comment. A slug that is merely odd
 * still produces a valid Application and a valid namespace, and then addresses the WRONG (or a
 * nonexistent) Vault path: the pods stay Pending on their Secret mounts, which is loud, or —
 * worse, if it collides with another domain's slug — two tenants read one credential document.
 * Hence UNIQUE in the schema ({@code uq_domain_registry_ns_prefix}) and refused here.
 *
 * <h3>The rule</h3>
 * A DNS-1123 LABEL: lowercase alphanumerics and {@code -}, starting and ending alphanumeric.
 * Capped at {@link #MAX_LENGTH} = 59 rather than a label's own 63, because the value that has
 * to be a legal Kubernetes namespace is {@code <slug>-pki} &mdash; four characters longer.
 *
 * <p>Pure and side-effect free; no Spring, no I/O.
 */
public final class DomainSlug {

    /**
     * Longest accepted slug. A Kubernetes namespace is a DNS-1123 label (max 63) and the
     * namespace derived from a slug is {@code <slug>-pki}, so the slug itself gets 63 - 4.
     */
    public static final int MAX_LENGTH = 59;

    private static final Pattern DNS_1123_LABEL =
            Pattern.compile("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$");

    private DomainSlug() {
    }

    /**
     * Why this value cannot be a slug, or empty when it can.
     *
     * @return a human-readable refusal reason (safe to return to a SUPERADMIN caller), or
     *         {@link Optional#empty()} when {@code slug} is acceptable
     */
    public static Optional<String> refusalReason(String slug) {
        if (slug == null || slug.isBlank()) {
            return Optional.of(
                    "nsPrefix is required: it is the domain's slug (decision 29a) and names the "
                            + "tenant namespace <nsPrefix>-pki, the ArgoCD Application "
                            + "casdoor-<nsPrefix> and the Vault path secret/<nsPrefix>/casdoor");
        }
        if (!slug.equals(slug.trim())) {
            return Optional.of("nsPrefix must not have leading or trailing whitespace");
        }
        if (slug.length() > MAX_LENGTH) {
            return Optional.of(
                    "nsPrefix is too long (" + slug.length() + " > " + MAX_LENGTH
                            + "): the derived namespace <nsPrefix>-pki must be a DNS-1123 label "
                            + "of at most 63 characters");
        }
        if (!DNS_1123_LABEL.matcher(slug).matches()) {
            return Optional.of(
                    "nsPrefix must be a DNS-1123 label (lowercase alphanumerics and '-', "
                            + "starting and ending alphanumeric): got '" + slug + "'");
        }
        return Optional.empty();
    }

    /** Whether {@code slug} satisfies the decision-29a rule. */
    public static boolean isValid(String slug) {
        return refusalReason(slug).isEmpty();
    }

    /** The tenant PKI namespace a slug expands into &mdash; the ApplicationSet's destination. */
    public static String pkiNamespace(String slug) {
        return slug + "-pki";
    }

    /** The Vault KV path a slug expands into &mdash; the per-domain credential document. */
    public static String vaultPath(String slug) {
        return "secret/" + slug + "/casdoor";
    }

    /**
     * Whether a database error is the slug-uniqueness violation
     * ({@code uq_domain_registry_ns_prefix}, changelog 012).
     *
     * <p>The service checks slug uniqueness before inserting, so this only fires on the RACE —
     * two SUPERADMINs registering different domains with the same slug at once. Without it that
     * race surfaces as a raw {@code DuplicateKeyException} and the caller gets a 500 for what is
     * squarely a 409. Matched on the constraint NAME anywhere in the throwable chain, the way
     * {@link McsCategoryAllocator#isCategoryCollision(Throwable)} does.
     */
    public static boolean isSlugCollision(Throwable error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            String message = t.getMessage();
            if (message != null
                    && message.toLowerCase(java.util.Locale.ROOT)
                            .contains("uq_domain_registry_ns_prefix")) {
                return true;
            }
            if (t.getCause() == t) {
                break;
            }
        }
        return false;
    }
}
