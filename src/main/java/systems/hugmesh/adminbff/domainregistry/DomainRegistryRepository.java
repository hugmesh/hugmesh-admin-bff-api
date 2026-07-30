package systems.hugmesh.adminbff.domainregistry;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code domain_registry} — the RUNTIME source of truth for
 * the cluster's brands/domains (schema in Liquibase
 * {@code db/changelog/012-domain-registry.xml}).
 *
 * <p>Backed by the Spring Data {@link DomainRegistryRowRepository} (no raw
 * {@code DatabaseClient}); maps the {@link DomainRegistryRow} entity to the {@link
 * DomainRegistration} domain record. Every query is UNSCOPED (the registry of brands;
 * the controller {@code hasRole('SUPERADMIN')} is the gate). No delete — a domain is
 * soft-disabled via {@link #update}.
 */
@Repository
public class DomainRegistryRepository {

    private final DomainRegistryRowRepository repo;

    public DomainRegistryRepository(DomainRegistryRowRepository repo) {
        this.repo = repo;
    }

    /**
     * Insert a new domain (app-generated id), stamping {@code created_by_subject}. A
     * duplicate {@code cluster_domain} surfaces as the DB unique-violation (the backstop
     * against a race; the caller runs the idempotency check first).
     */
    public Mono<DomainRegistration> insert(DomainRegistration d, String createdBySubject) {
        Instant now = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id hands back the generated string, which we read back by that id to
        // return the persisted row (provisioning-status columns default false/false/0).
        return repo.insertReturningId(d.clusterDomain(), d.brand(), d.org(), d.caRef(),
                        d.nsPrefix(), d.casdoorOrg(), d.meshTag(), d.enabled(), now,
                        createdBySubject, now)
                .flatMap(genId -> repo.findById(genId).map(DomainRegistryRow::toDomain));
    }

    /** Every registered domain (the SUPERADMIN list surface). Ordered by the natural key. */
    public Flux<DomainRegistration> findAll() {
        return repo.findAllByOrderByClusterDomain().map(DomainRegistryRow::toDomain);
    }

    /** The domain with this {@code cluster_domain}, if any. */
    public Mono<DomainRegistration> findByClusterDomain(String clusterDomain) {
        return repo.findByClusterDomain(clusterDomain).map(DomainRegistryRow::toDomain);
    }

    /**
     * Update the MUTABLE fields of an existing domain (matched by {@code cluster_domain})
     * and re-read the row. The PK ({@code id}), {@code cluster_domain}, {@code created_at}
     * and {@code created_by_subject} are IMMUTABLE — only brand/org/ca_ref/ns_prefix/
     * casdoor_org/mesh_tag/enabled change (and {@code updated_at} is bumped). Empty if no
     * domain with that {@code cluster_domain} exists.
     *
     * <p>The provisioning-status fields ({@code ca_provisioned} / {@code appset_registered} /
     * {@code last_reconciled_generation}, band 190) are PRESERVED from the existing row — the
     * SUPERADMIN CRUD update NEVER touches them (they are the later reconcile effector's
     * write surface). Carrying them through (rather than the false/false/0 default) means a
     * soft-disable / rename does not clobber a domain's recorded provisioning state.
     */
    public Mono<DomainRegistration> update(DomainRegistration d) {
        return repo.findByClusterDomain(d.clusterDomain())
                .flatMap(existing -> {
                    DomainRegistryRow updated = new DomainRegistryRow(
                            existing.id(), existing.clusterDomain(), d.brand(), d.org(), d.caRef(),
                            d.nsPrefix(), d.casdoorOrg(), d.meshTag(), d.enabled(),
                            existing.createdAt(), existing.createdBySubject(), Instant.now(),
                            // preserve provisioning-status (effector-owned; CRUD never mutates).
                            existing.caProvisioned(), existing.appsetRegistered(),
                            existing.lastReconciledGeneration(), false);
                    return repo.save(updated).map(DomainRegistryRow::toDomain);
                });
    }
}
