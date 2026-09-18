package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code PUT /bff/admin/domains/{clusterDomain}} (SUPERADMIN) — updates the
 * MUTABLE descriptors of an existing {@code domain_registry} row (schema 012). The
 * {@code clusterDomain} natural key comes from the PATH and is IMMUTABLE (so is the
 * row's {@code id}, {@code created_at} and {@code created_by_subject}) — only the brand
 * descriptors and the {@code enabled} desired-state flag change. A domain is disabled by
 * sending {@code enabled:false} (the SOFT-DISABLE — there is no hard delete).
 */
public record UpdateDomainRequest(
        @Size(max = 64, message = "brand is too long")
        @Nullable
        String brand,

        @Size(max = 255, message = "org is too long")
        @Nullable
        String org,

        @Size(max = 512, message = "caRef is too long")
        @Nullable
        String caRef,

        /** The domain's SLUG. IMMUTABLE after create (decision 29a): {@code null} (omitted)
         *  and the CURRENT value are both accepted, a DIFFERENT value is refused with a 409.
         *  Renaming it would re-point the Vault path {@code secret/<slug>/casdoor} at a
         *  document that does not exist, and rename the ArgoCD Application (pruning the old
         *  instance), so it is a de-provision plus a re-provision, never an update. */
        @Size(max = 64, message = "nsPrefix is too long")
        @Nullable
        String nsPrefix,

        @Size(max = 255, message = "casdoorOrg is too long")
        @Nullable
        String casdoorOrg,

        @Size(max = 64, message = "meshTag is too long")
        @Nullable
        String meshTag,

        /** Desired-state on/off. {@code null} (omitted) leaves the current value
         *  unchanged; {@code false} is the SOFT-DISABLE. */
        @Nullable
        Boolean enabled,

        /** Which Casdoor serves this domain's sign-in (decision 29b): {@code own} or
         *  {@code superdomain}. {@code null} (omitted) leaves the current value unchanged.
         *  NOTE that flipping {@code own -> superdomain} is what would later PRUNE a
         *  per-domain IdP instance, and the generator's removal runbook requires the domain's
         *  tenancy-registry pair to be retired FIRST; nothing in this repo materialises that
         *  yet, so the flip is inert today. */
        @Size(max = 16, message = "idp is too long")
        @Nullable
        String idp) {
}
