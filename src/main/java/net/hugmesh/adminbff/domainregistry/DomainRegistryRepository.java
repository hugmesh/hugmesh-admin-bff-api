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
                        pair.level(), pair.levelPg(), d.brandTitle(), d.headscaleUrl())
                .flatMap(genId -> repo.findById(genId).map(DomainRegistryRow::toDomain));
    }

    /**
     * The category pair this insert will carry: the caller's explicit pair when it supplied a
     * complete one, else the lowest free pair given every {@code selinux_level} already stored.
     */
    private Mono<McsCategoryAllocator.McsPair> allocateFor(DomainRegistration d) {
        return McsCategoryAllocator.pairOf(d.selinuxLevel(), d.selinuxLevelPg())
                .map(DomainRegistryRepository::checkedExplicitPair)
                .orElseGet(() -> takenLevels().map(McsCategoryAllocator::allocate));
    }

    /**
     * Every non-blank {@code selinux_level} currently stored — the allocator's taken set.
     *
     * <p>FILTER BEFORE MAP. A row registered before decision 29 has a NULL {@code selinux_level},
     * and Reactor's {@code map} refuses a null result with a NullPointerException. The original
     * {@code map(selinuxLevel).filter(nonNull)} order therefore made EVERY insert fail with a 500
     * as soon as one pre-decision row existed — exactly the rows allocate-now exists to repair.
     */
    private Mono<java.util.List<String>> takenLevels() {
        return repo.findAll()
                .filter(row -> row.selinuxLevel() != null && !row.selinuxLevel().isBlank())
                .map(DomainRegistryRow::selinuxLevel)
                .collectList();
    }

    /** Whether the registry holds no row at all (the first-start import's precondition). */
    public Mono<Boolean> isEmpty() {
        return repo.count().map(n -> n == 0L);
    }

    /**
     * Record a node agent's reconcile ACK (decision 89b): {@code appset_registered} and a
     * STRICTLY-INCREASING {@code last_reconciled_generation}, never {@code ca_provisioned}.
     * Emits the rows updated: {@code 1} when the ack advanced the row, {@code 0} when the domain
     * is unknown OR the generation is not newer than the stored one.
     */
    public Mono<Long> recordReconcileAck(String clusterDomain, boolean appsetRegistered,
                                         long generation) {
        return repo.recordReconcileAck(clusterDomain, appsetRegistered, generation, Instant.now());
    }

    /**
     * The SUPERADMIN "allocate now" write (decision 89c) for a row registered before decision 29:
     * store {@code slug} (the row's own slug when it already has one) and an MCS pair (the row's
     * own pair when it already has one, else the lowest free pair) in ONE compare-and-set UPDATE.
     *
     * <p>Same collision discipline as {@link #insert}: a pair taken concurrently by another row
     * trips {@code uq_domain_registry_selinux_level*}, and the allocation is retried against a
     * re-read taken set up to {@link #MCS_ALLOCATION_ATTEMPTS} times. Every other error (the
     * {@code ns_prefix} UNIQUE violation included) propagates. EMPTY when the compare-and-set
     * matched no row — a concurrent allocate got there first.
     */
    public Mono<DomainRegistration> allocateNow(DomainRegistration current, String slug) {
        return allocateNowAttempt(current, slug, 1);
    }

    private Mono<DomainRegistration> allocateNowAttempt(DomainRegistration current, String slug,
                                                        int attempt) {
        Mono<McsCategoryAllocator.McsPair> pair =
                McsCategoryAllocator.pairOf(current.selinuxLevel(), current.selinuxLevelPg())
                        .map(Mono::just)
                        .orElseGet(() -> takenLevels().map(McsCategoryAllocator::allocate));
        return pair
                .flatMap(p -> repo.allocateNow(current.id(), slug, p.level(), p.levelPg(),
                        Instant.now()))
                .flatMap(updated -> updated == 1L
                        ? repo.findById(current.id()).map(DomainRegistryRow::toDomain)
                        : Mono.<DomainRegistration>empty())
                .onErrorResume(e -> McsCategoryAllocator.isCategoryCollision(e)
                                && attempt < MCS_ALLOCATION_ATTEMPTS
                        ? allocateNowAttempt(current, slug, attempt + 1)
                        : Mono.error(e));
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
     * casdoor_org/mesh_tag/enabled/idp/brand_title/headscale_url change (and {@code updated_at}
     * is bumped). Empty if no domain with that {@code cluster_domain} exists.
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
                existing.selinuxLevel(), existing.selinuxLevelPg(),
                d.brandTitle(), d.headscaleUrl(), false);
    }
}
