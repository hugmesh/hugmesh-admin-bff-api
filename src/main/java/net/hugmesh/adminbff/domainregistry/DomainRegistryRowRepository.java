package net.hugmesh.adminbff.domainregistry;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code domain_registry} (changeset 012). All
 * queries are UNSCOPED (the registry OF brands; SUPERADMIN-only). Derived finders cover
 * the natural-key-ordered list + the cluster_domain lookup; the UPDATE composes
 * {@code save}. The {@link DomainRegistryRepository} facade maps rows to/from {@link
 * DomainRegistration}.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 * A duplicate {@code cluster_domain} still surfaces the UNIQUE-violation (no ON CONFLICT)
 * — the race backstop the facade + service rely on.
 */
public interface DomainRegistryRowRepository extends ReactiveCrudRepository<DomainRegistryRow, String> {

    /**
     * Insert a new domain with a DB-generated id (id OMITTED → filled from the column
     * DEFAULT; {@code RETURNING id} reads the generated varchar(36) back). The
     * provisioning-status columns ({@code ca_provisioned}/{@code appset_registered}/{@code
     * last_reconciled_generation}, band 190) are OMITTED → they take their DB DEFAULT
     * false/false/0 (exactly the fresh-domain shape the effector later flips). The supplied
     * columns match the {@link DomainRegistryRow} column order (id + the three
     * provisioning-status columns excluded).
     *
     * <p>DECISION 29 (2026-09-17): {@code idp} and the MCS pair {@code selinux_level} /
     * {@code selinux_level_pg} are supplied EXPLICITLY by this INSERT — the pair is what
     * {@link McsCategoryAllocator} allocated for this row. That is deliberate: the allocation
     * has to be part of the insert statement so the
     * {@code uq_domain_registry_selinux_level}/{@code _pg} constraints arbitrate a concurrent
     * allocation. {@code idp} would otherwise take its {@code superdomain} column default; it
     * is passed explicitly so the request's value reaches the row.
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO domain_registry \
            (cluster_domain, brand, org, ca_ref, ns_prefix, casdoor_org, mesh_tag, enabled, \
             created_at, created_by_subject, updated_at, idp, selinux_level, selinux_level_pg) \
            VALUES (:cluster_domain, :brand, :org, :ca_ref, :ns_prefix, :casdoor_org, \
             :mesh_tag, :enabled, :created_at, :created_by_subject, :updated_at, \
             :idp, :selinux_level, :selinux_level_pg) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("cluster_domain") String clusterDomain,
                                   @Param("brand") String brand,
                                   @Param("org") String org,
                                   @Param("ca_ref") String caRef,
                                   @Param("ns_prefix") String nsPrefix,
                                   @Param("casdoor_org") String casdoorOrg,
                                   @Param("mesh_tag") String meshTag,
                                   @Param("enabled") boolean enabled,
                                   @Param("created_at") Instant createdAt,
                                   @Param("created_by_subject") String createdBySubject,
                                   @Param("updated_at") Instant updatedAt,
                                   @Param("idp") String idp,
                                   @Param("selinux_level") String selinuxLevel,
                                   @Param("selinux_level_pg") String selinuxLevelPg);

    /** Every registered domain, natural-key ordered ({@code ORDER BY cluster_domain}). */
    Flux<DomainRegistryRow> findAllByOrderByClusterDomain();

    /** The domain with this {@code cluster_domain}, if any (the UNIQUE natural-key lookup). */
    Mono<DomainRegistryRow> findByClusterDomain(String clusterDomain);

    /**
     * The domain holding this SLUG, if any (decision 29a: {@code ns_prefix} IS the slug, and it
     * is UNIQUE — {@code uq_domain_registry_ns_prefix}). The find-before-insert check behind the
     * service's clean 409; the constraint remains the race backstop.
     */
    Mono<DomainRegistryRow> findByNsPrefix(String nsPrefix);
}
