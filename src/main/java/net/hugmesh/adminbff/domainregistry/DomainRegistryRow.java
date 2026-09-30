package net.hugmesh.adminbff.domainregistry;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code domain_registry} (Liquibase changeset 012) — the durable shape for a
 * {@link DomainRegistration}. PK is a {@code varchar(36)} app-generated UUID string;
 * {@code cluster_domain} is the UNIQUE natural key. Implements {@link Persistable} so a
 * freshly-minted row INSERTs. {@link DomainRegistration} stays the domain record;
 * {@link DomainRegistryRepository} maps between the two.
 */
@Table("domain_registry")
public record DomainRegistryRow(
        @Id @Column("id") String id,
        @Column("cluster_domain") String clusterDomain,
        @Column("brand") String brand,
        @Column("org") String org,
        @Column("ca_ref") String caRef,
        @Column("ns_prefix") String nsPrefix,
        @Column("casdoor_org") String casdoorOrg,
        @Column("mesh_tag") String meshTag,
        @Column("enabled") boolean enabled,
        @Column("created_at") Instant createdAt,
        @Column("created_by_subject") String createdBySubject,
        @Column("updated_at") Instant updatedAt,
        // Provisioning-status (Liquibase band 190) — DB default false/false/0; flipped ONLY
        // by the later generator domain-reconcile effector (ships dark; see DomainRegistration).
        @Column("ca_provisioned") boolean caProvisioned,
        @Column("appset_registered") boolean appsetRegistered,
        @Column("last_reconciled_generation") long lastReconciledGeneration,
        // Decision 29 (operator, 2026-09-17) — the three columns the generator's per-domain
        // element schema needed and this row could not supply. Appended to changelog 012.
        @Column("idp") String idp,
        @Column("selinux_level") String selinuxLevel,
        @Column("selinux_level_pg") String selinuxLevelPg,
        // Decision 87e (operator, 2026-09-23) — Liquibase 380. NULL = not set by the SUPERADMIN.
        @Column("brand_title") String brandTitle,
        @Column("headscale_url") String headscaleUrl,
        @Transient boolean isNew) implements Persistable<String> {

    @org.springframework.data.annotation.PersistenceCreator
    public DomainRegistryRow(String id, String clusterDomain, String brand, String org, String caRef,
                             String nsPrefix, String casdoorOrg, String meshTag, boolean enabled,
                             Instant createdAt, String createdBySubject, Instant updatedAt,
                             boolean caProvisioned, boolean appsetRegistered,
                             long lastReconciledGeneration, String idp, String selinuxLevel,
                             String selinuxLevelPg, String brandTitle, String headscaleUrl) {
        this(id, clusterDomain, brand, org, caRef, nsPrefix, casdoorOrg, meshTag, enabled,
                createdAt, createdBySubject, updatedAt, caProvisioned, appsetRegistered,
                lastReconciledGeneration, idp, selinuxLevel, selinuxLevelPg, brandTitle,
                headscaleUrl, false);
    }

    /** Pre-decision-87e 18-arg shape: {@code brand_title} / {@code headscale_url} unset. */
    public DomainRegistryRow(String id, String clusterDomain, String brand, String org, String caRef,
                             String nsPrefix, String casdoorOrg, String meshTag, boolean enabled,
                             Instant createdAt, String createdBySubject, Instant updatedAt,
                             boolean caProvisioned, boolean appsetRegistered,
                             long lastReconciledGeneration, String idp, String selinuxLevel,
                             String selinuxLevelPg) {
        this(id, clusterDomain, brand, org, caRef, nsPrefix, casdoorOrg, meshTag, enabled,
                createdAt, createdBySubject, updatedAt, caProvisioned, appsetRegistered,
                lastReconciledGeneration, idp, selinuxLevel, selinuxLevelPg, null, null, false);
    }

    /**
     * Pre-decision-29 15-arg shape (band-190 columns, no idp / MCS pair). Defaults {@code idp}
     * to the {@link DomainIdp#SUPERDOMAIN} floor and leaves the MCS pair UNALLOCATED
     * ({@code null}) — never a guessed category, because a wrong category silently co-locates
     * two workloads (docs/SECURITY.md §3) while a missing one fails closed at provisioning.
     */
    public DomainRegistryRow(String id, String clusterDomain, String brand, String org, String caRef,
                             String nsPrefix, String casdoorOrg, String meshTag, boolean enabled,
                             Instant createdAt, String createdBySubject, Instant updatedAt,
                             boolean caProvisioned, boolean appsetRegistered,
                             long lastReconciledGeneration) {
        this(id, clusterDomain, brand, org, caRef, nsPrefix, casdoorOrg, meshTag, enabled,
                createdAt, createdBySubject, updatedAt, caProvisioned, appsetRegistered,
                lastReconciledGeneration, DomainIdp.SUPERDOMAIN, null, null, null, null, false);
    }

    /**
     * Back-compat constructor for the pre-band-190 12-arg insert/update path (the CRUD never
     * sets the provisioning-status fields). Defaults the three status fields to the
     * unprovisioned floor (false/false/0) = the DB column defaults, so a freshly INSERTed row
     * carries the same values the DB would. {@code isNew} stays {@code false}.
     */
    public DomainRegistryRow(String id, String clusterDomain, String brand, String org, String caRef,
                             String nsPrefix, String casdoorOrg, String meshTag, boolean enabled,
                             Instant createdAt, String createdBySubject, Instant updatedAt) {
        this(id, clusterDomain, brand, org, caRef, nsPrefix, casdoorOrg, meshTag, enabled,
                createdAt, createdBySubject, updatedAt, false, false, 0L,
                DomainIdp.SUPERDOMAIN, null, null, null, null, false);
    }

    /** Full 13-arg shape WITH an explicit {@code isNew} (the create-path INSERT marker),
     *  defaulting the provisioning-status fields to the unprovisioned floor (false/false/0). */
    public DomainRegistryRow(String id, String clusterDomain, String brand, String org, String caRef,
                             String nsPrefix, String casdoorOrg, String meshTag, boolean enabled,
                             Instant createdAt, String createdBySubject, Instant updatedAt,
                             boolean isNew) {
        this(id, clusterDomain, brand, org, caRef, nsPrefix, casdoorOrg, meshTag, enabled,
                createdAt, createdBySubject, updatedAt, false, false, 0L,
                DomainIdp.SUPERDOMAIN, null, null, null, null, isNew);
    }

    DomainRegistration toDomain() {
        return new DomainRegistration(id, clusterDomain, brand, org, caRef, nsPrefix,
                casdoorOrg, meshTag, enabled, createdAt, createdBySubject, updatedAt,
                caProvisioned, appsetRegistered, lastReconciledGeneration,
                idp, selinuxLevel, selinuxLevelPg, brandTitle, headscaleUrl);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
