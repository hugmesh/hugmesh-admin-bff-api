package net.hugmesh.adminbff.domainregistry;

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
     * Insert a new domain (DB-generated id), stamping {@code created_by_subject} and
     * ALLOCATING the row's MCS category pair. A duplicate {@code cluster_domain} (or
     * {@code ns_prefix}) surfaces as the DB unique-violation (the backstop against a race;
     * the caller runs the idempotency check first).
     *
     * <h3>MCS allocation — operator decision 29c</h3>
     * <em>"the domain_registry writer allocates selinuxLevel / selinuxLevelPg at insert, under
     * a uniqueness constraint"</em>. This method IS that writer. It reads the categories
     * already taken, asks {@link McsCategoryAllocator} for the lowest free pair, and writes it
     * in the same INSERT — so the {@code uq_domain_registry_selinux_level}/{@code _pg}
     * constraints, not the read, decide who wins a race. A losing insert is RETRIED against a
     * re-read taken-set, up to {@link #MCS_ALLOCATION_ATTEMPTS} times; every other error
     * (including the {@code cluster_domain} duplicate the caller maps to a 409) propagates
     * untouched, because retrying THAT would turn a legitimate conflict into a hang.
     *
     * <p>An explicit pair on the incoming {@link DomainRegistration} is honoured rather than
     * re-allocated: it is how a future reconcile/import path can restate an existing domain's
     * categories without them drifting. The UNIQUE constraints still arbitrate.
     */
    public Mono<DomainRegistration> insert(DomainRegistration d, String createdBySubject) {
        return insertAttempt(d, createdBySubject, 1);
    }

    /**
     * How many times an MCS-category collision is re-allocated before giving up. A collision
     * means another SUPERADMIN registered a domain between this call's read and its insert;
     * each retry re-reads, so N concurrent writers need at most N attempts. Bounded so a
     * genuinely stuck constraint surfaces instead of spinning.
     */
    static final int MCS_ALLOCATION_ATTEMPTS = 5;

    private Mono<DomainRegistration> insertAttempt(DomainRegistration d, String createdBySubject,
                                                   int attempt) {
        return allocateFor(d)
                .flatMap(pair -> insertWith(d, createdBySubject, pair))
                .onErrorResume(e -> McsCategoryAllocator.isCategoryCollision(e)
                                && attempt < MCS_ALLOCATION_ATTEMPTS
                        ? insertAttempt(d, createdBySubject, attempt + 1)
                        : Mono.error(e));
    }

    /**
     * The INSERT itself, carrying one allocated category pair. The id is OMITTED (filled from
     * the {@code (gen_random_uuid())::text} column DEFAULT, changelog 200) and
     * {@code RETURNING id} hands back the generated string, which we read back by that id to
     * return the persisted row (provisioning-status columns default false/false/0).
     */
    private Mono<DomainRegistration> insertWith(DomainRegistration d, String createdBySubject,
                                                McsCategoryAllocator.McsPair pair) {
        Instant now = Instant.now();
        return repo.insertReturningId(d.clusterDomain(), d.brand(), d.org(), d.caRef(),
                        d.nsPrefix(), d.casdoorOrg(), d.meshTag(), d.enabled(), now,
                        createdBySubject, now, DomainIdp.normalize(d.idp()),
                        pair.level(), pair.levelPg())
                .flatMap(genId -> repo.findById(genId).map(DomainRegistryRow::toDomain));
    }

    /**
     * The category pair this insert will carry: the caller's explicit pair when it supplied a
     * complete one, else the lowest free pair given every {@code selinux_level} already stored.
     */
    private Mono<McsCategoryAllocator.McsPair> allocateFor(DomainRegistration d) {
        return McsCategoryAllocator.pairOf(d.selinuxLevel(), d.selinuxLevelPg())
                .map(DomainRegistryRepository::checkedExplicitPair)
                .orElseGet(() -> repo.findAll()
                        .map(DomainRegistryRow::selinuxLevel)
                        .filter(level -> level != null && !level.isBlank())
                        .collectList()
                        .map(McsCategoryAllocator::allocate));
    }

    /**
     * An explicit pair is honoured only from inside the RESERVED per-domain range. Nothing
     * supplies one today; the javadoc above invites a future reconcile/import caller to, and
     * that caller must not be able to store a category from the static per-application matrix —
     * hugmesh-generator {@code docs/DOMAIN-IDP.md:56} forbids the base's {@code s0:c85} /
     * {@code s0:c86} placeholders going live, and a platform category on a tenant pod removes
     * the isolation silently. The UNIQUE constraints cannot catch it: those values are unique.
     */
    private static Mono<McsCategoryAllocator.McsPair> checkedExplicitPair(
            McsCategoryAllocator.McsPair pair) {
        if (!McsCategoryAllocator.isInReservedRange(pair.level())
                || !McsCategoryAllocator.isInReservedRange(pair.levelPg())) {
            return Mono.error(new IllegalArgumentException(
                    "explicit MCS pair (" + pair.level() + ", " + pair.levelPg() + ") is outside "
                            + "the reserved per-domain range s0:c" + McsCategoryAllocator.FLOOR_CATEGORY
                            + "..s0:c" + McsCategoryAllocator.CEILING_CATEGORY
                            + " — a category from the static per-application matrix (or the "
                            + "forbidden s0:c85/s0:c86 placeholders) would silently co-locate a "
                            + "tenant workload with a platform one"));
        }
        return Mono.just(pair);
    }

    /** Every registered domain (the SUPERADMIN list surface). Ordered by the natural key. */
    public Flux<DomainRegistration> findAll() {
        return repo.findAllByOrderByClusterDomain().map(DomainRegistryRow::toDomain);
    }

    /** The domain with this {@code cluster_domain}, if any. */
    public Mono<DomainRegistration> findByClusterDomain(String clusterDomain) {
        return repo.findByClusterDomain(clusterDomain).map(DomainRegistryRow::toDomain);
    }

    /** The domain holding this SLUG ({@code ns_prefix}, decision 29a), if any. */
    public Mono<DomainRegistration> findByNsPrefix(String nsPrefix) {
        return repo.findByNsPrefix(nsPrefix).map(DomainRegistryRow::toDomain);
    }

    /**
     * Update the MUTABLE fields of an existing domain (matched by {@code cluster_domain})
     * and re-read the row. The PK ({@code id}), {@code cluster_domain}, {@code created_at}
     * and {@code created_by_subject} are IMMUTABLE — only brand/org/ca_ref/ns_prefix/
     * casdoor_org/mesh_tag/enabled change (and {@code updated_at} is bumped). Empty if no
     * domain with that {@code cluster_domain} exists.
     *
     * <p>DECISION 29: {@code ns_prefix} joins that immutable set — it is the domain's SLUG,
     * and it names the Vault path as well as the namespace and the Application, so a rename is
     * a de-provision plus a re-provision, never an UPDATE. The MCS pair
     * ({@code selinux_level} / {@code selinux_level_pg}) is likewise preserved: it was
     * allocated at insert and belongs to a possibly-running workload. {@code idp} IS mutable.
     *
     * <p>The provisioning-status fields ({@code ca_provisioned} / {@code appset_registered} /
     * {@code last_reconciled_generation}, band 190) are PRESERVED from the existing row — the
     * SUPERADMIN CRUD update NEVER touches them (they are the later reconcile effector's
     * write surface). Carrying them through (rather than the false/false/0 default) means a
     * soft-disable / rename does not clobber a domain's recorded provisioning state.
     */
    public Mono<DomainRegistration> update(DomainRegistration d) {
        return repo.findByClusterDomain(d.clusterDomain())
                .flatMap(existing -> repo.save(mergeOnto(existing, d))
                        .map(DomainRegistryRow::toDomain));
    }

    /**
     * The row to persist: the caller's mutable fields over the STORED immutables.
     *
     * <p>{@code ns_prefix} is the SLUG (decision 29a) and immutable after create — the service
     * refuses a change with a 409, and this carries the stored value through so no path can
     * rewrite it, because renaming the slug re-points the Vault path
     * {@code secret/<slug>/casdoor} at a document that does not exist. The provisioning-status
     * trio is effector-owned and preserved. {@code idp} IS mutable (the own/superdomain flip);
     * the MCS pair is NOT — it was allocated at insert, and re-allocating it would move a live
     * workload's SELinux category out from under it.
     */
    private static DomainRegistryRow mergeOnto(DomainRegistryRow existing, DomainRegistration d) {
        return new DomainRegistryRow(
                existing.id(), existing.clusterDomain(), d.brand(), d.org(), d.caRef(),
                existing.nsPrefix(), d.casdoorOrg(), d.meshTag(), d.enabled(),
                existing.createdAt(), existing.createdBySubject(), Instant.now(),
                existing.caProvisioned(), existing.appsetRegistered(),
                existing.lastReconciledGeneration(), DomainIdp.normalize(d.idp()),
                existing.selinuxLevel(), existing.selinuxLevelPg(), false);
    }
}
