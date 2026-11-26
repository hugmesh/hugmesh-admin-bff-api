package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/admin/domains} (SUPERADMIN) — registers one brand/domain in
 * the runtime {@code domain_registry} (schema 012), the twin of a build-time
 * {@code brands/domains.conf} row. The {@code @NotBlank}/{@code @Size} guards make a
 * malformed registration a clean 400 (mapped by
 * {@link net.hugmesh.adminbff.web.ValidationExceptionHandler}) BEFORE any write;
 * the {@code cluster_domain} UNIQUE check is enforced in
 * {@link net.hugmesh.adminbff.domainregistry.DomainRegistryService} (a duplicate
 * is a clean 409).
 *
 * <ul>
 *   <li>{@code clusterDomain} — brands/domains.conf {@code DOMAIN}; the brand's base
 *       domain. REQUIRED + the UNIQUE natural key.</li>
 *   <li>{@code brand} — brands/domains.conf {@code BRAND}; the short slug.</li>
 *   <li>{@code caRef} — a CA *REFERENCE* (Vault PKI path / secret name / {@code
 *       "generate"}), folding the conf's {@code CA_CERT}/{@code CA_KEY}. NEVER the
 *       cert/key bytes or a private-key path.</li>
 *   <li>{@code org} / {@code nsPrefix} / {@code casdoorOrg} / {@code meshTag} — the
 *       runtime-superset descriptors the later ApplicationSet expands.</li>
 *   <li>{@code enabled} — desired-state on/off; defaults true (see the service) when the
 *       client omits it.</li>
 * </ul>
 */
public record CreateDomainRequest(
        @NotBlank(message = "clusterDomain is required")
        @Size(max = 253, message = "clusterDomain is too long")
        String clusterDomain,

        @Size(max = 64, message = "brand is too long")
        @Nullable
        String brand,

        @Size(max = 255, message = "org is too long")
        @Nullable
        String org,

        @Size(max = 512, message = "caRef is too long")
        @Nullable
        String caRef,

        /** The domain's SLUG (decision 29a): REQUIRED, DNS-1123 label, cluster-UNIQUE. It
         *  names the tenant namespace {@code <nsPrefix>-pki}, the ArgoCD Application and the
         *  Vault path {@code secret/<nsPrefix>/casdoor}, so it is validated in
         *  {@link net.hugmesh.adminbff.domainregistry.DomainSlug} (a 400) rather than merely
         *  length-checked. Kept {@code @Nullable} here so the refusal carries that full reason
         *  instead of a bare "must not be blank". */
        @Size(max = 64, message = "nsPrefix is too long")
        @Nullable
        String nsPrefix,

        @Size(max = 255, message = "casdoorOrg is too long")
        @Nullable
        String casdoorOrg,

        @Size(max = 64, message = "meshTag is too long")
        @Nullable
        String meshTag,

        /** Desired-state on/off. {@code null} (omitted) is treated as {@code true} by the
         *  service so a create defaults to an enabled domain. */
        @Nullable
        Boolean enabled,

        /** Which Casdoor serves this domain's sign-in (decision 29b):
         *  {@code superdomain} (the default when omitted &mdash; ride the mesh's central
         *  Casdoor, provisioning nothing per-domain) or {@code own} (the domain runs its own
         *  per-domain Casdoor). Anything else is a 400. */
        @Size(max = 16, message = "idp is too long")
        @Nullable
        String idp) {
}
