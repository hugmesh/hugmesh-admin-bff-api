package systems.hugmesh.adminbff.servicecatalog;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The data-driven per-service IDENTITY descriptor (the V7 leg) — replaces the hand-duplicated
 * ESO blocks + the static Vault role for-loop with ONE derivation from a
 * {@code (domain, serviceKey)} pair. Every per-service identity name the App-Store provisions
 * (the Casdoor role, the per-domain Vault PKI role, the ESO {@code ExternalSecret} name +
 * target secret + the mTLS common name) is derived deterministically here, so a NEW service
 * needs NO hand-edited ESO/Vault block — the effector + the generator's per-service template
 * read these fields.
 *
 * <p>The names mirror the platform's existing conventions:
 * <ul>
 *   <li>{@link #casdoorRole()} = {@code ROLE_<SERVICE>} (the same canonical {@code ROLE_<UPPER>}
 *       form {@code CasdoorAdminClient.ensureRoles} mints + the route-access rows reference);</li>
 *   <li>{@link #vaultPkiRole()} = {@code <domain>-<service>} (the per-domain Vault PKI role —
 *       per-domain so each brand's certs chain to that brand's CA, the multi-tenancy model);</li>
 *   <li>{@link #externalSecretName()} / {@link #targetSecretName()} =
 *       {@code <domain>-<service>-tls} (the ESO ExternalSecret + the k8s Secret it syncs);</li>
 *   <li>{@link #commonName()} = {@code <service>.<domain>} (the mTLS cert CN/SAN).</li>
 * </ul>
 *
 * <p>This is a PURE derivation (no I/O): admin-bff drives the Casdoor role from
 * {@link #casdoorRole()}; the generator's per-service ESO/Vault template renders from
 * {@link #toTemplateContext()} (a stable, ordered map). All inputs are sanitised to the
 * k8s-label/DNS-safe lowercase-alphanumeric-with-hyphens charset so a malformed serviceKey
 * can never inject into a manifest name.
 */
public record PerServiceIdentity(String domain, String serviceKey) {

    public PerServiceIdentity {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("domain is required");
        }
        if (serviceKey == null || serviceKey.isBlank()) {
            throw new IllegalArgumentException("serviceKey is required");
        }
    }

    /** The k8s/DNS-safe slug of a value: lowercase, non-alphanumerics → '-', collapsed,
     *  trimmed of leading/trailing '-'. Empty input collapses to a stable sentinel so a
     *  derived name is never blank. */
    public static String slug(String raw) {
        if (raw == null) {
            return "x";
        }
        String s = raw.toLowerCase(Locale.ROOT)
                .replace('.', '-')
                .replaceAll("[^a-z0-9-]", "-")
                .replaceAll("-+", "-")
                .replaceAll("(^-+)|(-+$)", "");
        return s.isEmpty() ? "x" : s;
    }

    private String domainSlug() {
        return slug(domain);
    }

    private String serviceSlug() {
        return slug(serviceKey);
    }

    /** The canonical Casdoor role for this service ({@code ROLE_<SERVICE>}). Matches the
     *  {@code ROLE_<UPPER>} form the rest of the platform mints. */
    public String casdoorRole() {
        return "ROLE_" + serviceSlug().replace('-', '_').toUpperCase(Locale.ROOT);
    }

    /** The per-domain Vault PKI role this service's certs are issued under. */
    public String vaultPkiRole() {
        return domainSlug() + "-" + serviceSlug();
    }

    /** The ESO ExternalSecret name (per-domain, per-service). */
    public String externalSecretName() {
        return domainSlug() + "-" + serviceSlug() + "-tls";
    }

    /** The k8s Secret the ExternalSecret syncs the issued cert into. */
    public String targetSecretName() {
        return domainSlug() + "-" + serviceSlug() + "-tls";
    }

    /** The per-domain backend namespace the service deploys into ({@code <domain>-be}). */
    public String destNamespace() {
        return domainSlug() + "-be";
    }

    /** The per-domain external (be) gateway whose route-access table the service's rule is
     *  added to ({@code <domain>-be-gateway}, the per-brand be-gateway convention). */
    public String domainSlugGateway() {
        return domainSlug() + "-be-gateway";
    }

    /** The external URL pattern the service's route-access rule grants ({@code /api/<service>/}).
     *  A prefix pattern (trailing slash) matching the gateway's url_pattern convention. */
    public String urlPattern() {
        return "/api/" + serviceSlug() + "/";
    }

    /** The mTLS certificate common name / primary SAN ({@code <service>.<domain>}). */
    public String commonName() {
        return serviceSlug() + "." + domain.toLowerCase(Locale.ROOT);
    }

    /**
     * The stable, ordered render context the generator's per-service ESO/Vault/cert template
     * consumes — the data-driven replacement for a hand-edited ESO block. Insertion-ordered
     * so a rendered manifest is byte-stable across runs.
     */
    public Map<String, String> toTemplateContext() {
        Map<String, String> ctx = new LinkedHashMap<>();
        ctx.put("domain", domain.toLowerCase(Locale.ROOT));
        ctx.put("domainSlug", domainSlug());
        ctx.put("serviceKey", serviceKey);
        ctx.put("serviceSlug", serviceSlug());
        ctx.put("casdoorRole", casdoorRole());
        ctx.put("vaultPkiRole", vaultPkiRole());
        ctx.put("externalSecretName", externalSecretName());
        ctx.put("targetSecretName", targetSecretName());
        ctx.put("destNamespace", destNamespace());
        ctx.put("commonName", commonName());
        return ctx;
    }
}
