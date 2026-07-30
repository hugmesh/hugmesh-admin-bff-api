package systems.hugmesh.adminbff.web.dto;

import systems.hugmesh.adminbff.domainregistry.DomainRegistration;

import java.time.Instant;

/**
 * Response view of a {@code domain_registry} row (schema 012 + the band-190 provisioning
 * status) — the full registry record returned by the SUPERADMIN domain endpoints. A straight
 * projection of {@link DomainRegistration} (no secrets: {@code caRef} is a reference, never
 * key material).
 *
 * <p>{@link #caProvisioned()} / {@link #appsetRegistered()} / {@link #lastReconciledGeneration()}
 * are the provisioning-status fields (band 190). They DEFAULT {@code false}/{@code false}/{@code 0}
 * and ship dark — only the later generator domain-reconcile effector flips them — so the
 * admin-ui Domains console can render the "registered but not yet provisioned" chip (the
 * platform-capability-gating mandate) off this read.
 */
public record DomainResponse(
        String id,
        String clusterDomain,
        String brand,
        String org,
        String caRef,
        String nsPrefix,
        String casdoorOrg,
        String meshTag,
        boolean enabled,
        Instant createdAt,
        String createdBySubject,
        Instant updatedAt,
        boolean caProvisioned,
        boolean appsetRegistered,
        long lastReconciledGeneration) {

    public static DomainResponse of(DomainRegistration d) {
        return new DomainResponse(d.id(), d.clusterDomain(), d.brand(), d.org(), d.caRef(),
                d.nsPrefix(), d.casdoorOrg(), d.meshTag(), d.enabled(), d.createdAt(),
                d.createdBySubject(), d.updatedAt(),
                d.caProvisioned(), d.appsetRegistered(), d.lastReconciledGeneration());
    }
}
