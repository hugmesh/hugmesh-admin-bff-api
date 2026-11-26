package net.hugmesh.adminbff.domainregistry;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.notification.SystemAccountProvisioner;
import net.hugmesh.adminbff.web.dto.CreateDomainRequest;
import net.hugmesh.adminbff.web.dto.UpdateDomainRequest;
import net.hugmesh.commons.web.ApiException;

/**
 * Write/read surface for {@code domain_registry} — the RUNTIME source of truth for the
 * cluster's brands/domains (multi-tenancy PR9), the SUPERADMIN-managed twin of the
 * build-time {@code brands/domains.conf}. SUPERADMIN-only (gated at
 * {@link net.hugmesh.adminbff.domainregistry.DomainRegistryController}); this is
 * the registry OF BRANDS, so it is inherently cross-domain and carries no per-row tenant
 * scope.
 *
 * <p>This is the PR9 FOUNDATION: the table + CRUD only. NO ApplicationSet wiring and NO
 * provisioning effector (ProvisionCa / ProvisionBrand) — those are later PRs.
 */
@Service
public class DomainRegistryService {

    private static final Logger log = LoggerFactory.getLogger(DomainRegistryService.class);

    private final DomainRegistryRepository repo;
    /**
     * The per-domain {@code @system} infra-account provisioner (Notifications PR3). A
     * brand-new domain gets its neutral notification sender provisioned at create-time —
     * BEST-EFFORT (a Casdoor failure never loses the registered domain row) and IDEMPOTENT
     * (re-running, e.g. via the SUPERADMIN re-provision endpoint, is a no-op). Nullable so
     * the existing unit constructor (and a Casdoor-less wiring) keep working unchanged; the
     * Spring-wired bean always supplies it.
     */
    @Nullable
    private final SystemAccountProvisioner systemAccount;

    @Autowired
    public DomainRegistryService(DomainRegistryRepository repo,
                                 @Nullable SystemAccountProvisioner systemAccount) {
        this.repo = repo;
        this.systemAccount = systemAccount;
    }

    /** Back-compat constructor (no @system provisioning) — used by the focused unit test
     *  that only exercises the registry CRUD contract. */
    public DomainRegistryService(DomainRegistryRepository repo) {
        this(repo, null);
    }

    /** Every registered domain (the SUPERADMIN list surface). */
    public Flux<DomainRegistration> list() {
        return repo.findAll();
    }

    /** A single domain by its {@code cluster_domain} natural key, or a 404. */
    public Mono<DomainRegistration> get(String clusterDomain) {
        return repo.findByClusterDomain(clusterDomain)
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "no domain registered for cluster_domain '" + clusterDomain + "'")));
    }

    /**
     * Register a new domain, stamping {@code created_by_subject} from the SUPERADMIN's
     * JWT subject. Validates the {@code cluster_domain} is non-blank and UNIQUE (a
     * find-before-insert check surfaces a clean 409; the DB UNIQUE index is the
     * race backstop, also mapped to 409). {@code enabled} defaults to {@code true} when
     * the request omits it.
     */
    public Mono<DomainRegistration> create(CreateDomainRequest req, String createdBySubject) {
        String clusterDomain = req.clusterDomain() == null ? null : req.clusterDomain().trim();
        if (clusterDomain == null || clusterDomain.isBlank()) {
            return Mono.error(ApiException.badRequest("clusterDomain is required"));
        }
        // DECISION 29a — nsPrefix IS the slug, so it is REQUIRED and DNS-1123 validated here.
        // Before this, a domain could be registered with no nsPrefix at all, or with one that
        // cannot be a Kubernetes namespace; either is unprovisionable, and the second only
        // surfaces as a failed sync long after the SUPERADMIN pressed save.
        var slugRefusal = DomainSlug.refusalReason(
                req.nsPrefix() == null ? null : req.nsPrefix().trim());
        if (slugRefusal.isPresent()) {
            return Mono.error(ApiException.badRequest(slugRefusal.get()));
        }
        // DECISION 29b — idp is a real column with a closed vocabulary; absent means superdomain.
        var idpRefusal = DomainIdp.refusalReason(req.idp());
        if (idpRefusal.isPresent()) {
            return Mono.error(ApiException.badRequest(idpRefusal.get()));
        }
        // DECISION 87e — brand_title / headscale_url are optional, but a value the brand-repo
        // renderer would refuse is refused HERE, not discovered later on a node.
        String brandTitle = emptyToNull(req.brandTitle());
        String headscaleUrl = emptyToNull(req.headscaleUrl());
        var brandRefusal = brandFieldRefusal(brandTitle, headscaleUrl);
        if (brandRefusal.isPresent()) {
            return Mono.error(ApiException.badRequest(brandRefusal.get()));
        }
        DomainRegistration draft = new DomainRegistration(
                null, clusterDomain, req.brand(), req.org(), req.caRef(), req.nsPrefix().trim(),
                req.casdoorOrg(), req.meshTag(),
                !Boolean.FALSE.equals(req.enabled()),
                null, createdBySubject, null, false, false, 0L,
                DomainIdp.normalize(req.idp()), null, null, brandTitle, headscaleUrl);
        String slug = req.nsPrefix().trim();
        return repo.findByClusterDomain(clusterDomain)
                .flatMap(existing -> Mono.<DomainRegistration>error(ApiException.conflict(
                        "domain '" + clusterDomain + "' is already registered")))
                // DECISION 29a: the slug is UNIQUE too, and for a sharper reason than the
                // natural key — two domains sharing it would read ONE Vault credential
                // document (secret/<slug>/casdoor). Checked before the insert so the common
                // case is a clean 409; uq_domain_registry_ns_prefix stays the race backstop.
                .switchIfEmpty(Mono.defer(() -> repo.findByNsPrefix(slug)
                        .flatMap(clash -> Mono.<DomainRegistration>error(ApiException.conflict(
                                "slug '" + slug + "' is already used by domain '"
                                        + clash.clusterDomain() + "'. The slug names the tenant "
                                        + "namespace, the ArgoCD Application and the Vault path "
                                        + DomainSlug.vaultPath(slug) + ", so it cannot be shared.")))))
                // No existing row: insert with @system provision hook and race backstop.
                .switchIfEmpty(Mono.defer(() -> insertDomainRegistration(draft, createdBySubject, clusterDomain, slug)));
    }

    /**
     * Update an existing domain's MUTABLE descriptors (matched by {@code cluster_domain}
     * from the path). {@code null} fields in the request leave the CURRENT value
     * unchanged (a partial PATCH-style merge); {@code enabled:false} is the SOFT-DISABLE.
     * The PK {@code id}, the {@code cluster_domain} natural key, {@code created_at} and
     * {@code created_by_subject} are IMMUTABLE. A 404 if no such domain exists.
     */
    public Mono<DomainRegistration> update(String clusterDomain, UpdateDomainRequest req) {
        var idpRefusal = req.idp() == null ? java.util.Optional.<String>empty()
                : DomainIdp.refusalReason(req.idp());
        if (idpRefusal.isPresent()) {
            return Mono.error(ApiException.badRequest(idpRefusal.get()));
        }
        // DECISION 87e: null leaves the stored value; "" clears it; anything else must pass the
        // renderer's rules.
        var brandRefusal = brandFieldRefusal(emptyToNull(req.brandTitle()),
                emptyToNull(req.headscaleUrl()));
        if (brandRefusal.isPresent()) {
            return Mono.error(ApiException.badRequest(brandRefusal.get()));
        }
        return repo.findByClusterDomain(clusterDomain)
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "no domain registered for cluster_domain '" + clusterDomain + "'")))
                // Merge mutable request fields onto the current row then persist.
                .flatMap(current -> mergeAndUpdateDomain(current, req));
    }

    /** Insert the new domain row, provision the @system account, and handle the duplicate-key race. */
    private Mono<DomainRegistration> insertDomainRegistration(DomainRegistration draft,
                                                               String createdBySubject,
                                                               String clusterDomain,
                                                               String slug) {
        return repo.insert(draft, createdBySubject)
                // DECISION 29c: the writer allocates the MCS pair, and an exhausted reserved
                // range is a refusal, never a wrap-around onto a live category. Mapped here so
                // it reaches the SUPERADMIN as a clean conflict with its reason, not a 500.
                .onErrorMap(McsCategoryAllocator.Exhausted.class,
                        ex -> ApiException.conflict(ex.getMessage()))
                .doOnNext(saved -> log.info(
                        "[domain-registry] registered cluster_domain={} brand={} by={} (id={})",
                        saved.clusterDomain(), saved.brand(), createdBySubject, saved.id()))
                // DOMAIN-CREATE HOOK: provision the per-domain @system notification sender.
                .flatMap(saved -> provisionSystemAccount(saved.clusterDomain()).thenReturn(saved))
                // Race backstop: a concurrent insert trips one of the two UNIQUE constraints.
                // The SLUG one is matched by constraint name rather than by re-reading, because
                // the winning row carries a DIFFERENT cluster_domain — a cluster_domain re-check
                // finds nothing and would let a DuplicateKeyException surface as a 500.
                .onErrorResume(e -> DomainSlug.isSlugCollision(e)
                        ? Mono.error(ApiException.conflict(
                                "slug '" + slug + "' was registered by another domain "
                                        + "concurrently; it names the Vault path "
                                        + DomainSlug.vaultPath(slug) + " and cannot be shared"))
                        : repo.findByClusterDomain(clusterDomain)
                                .flatMap(now -> Mono.<DomainRegistration>error(ApiException.conflict(
                                        "domain '" + clusterDomain + "' is already registered")))
                                .switchIfEmpty(Mono.error(e)));
    }

    /**
     * Merge mutable update-request fields onto the current row and persist.
     *
     * <p>DECISION 29a makes {@code nsPrefix} IMMUTABLE: omitting it, or restating the current
     * value, is accepted; a DIFFERENT value is refused with a 409 rather than silently ignored,
     * because the caller who sent it believes the slug changed. A slug rename re-points the
     * Vault path {@code secret/<slug>/casdoor} at a document that does not exist and renames
     * the ArgoCD Application (pruning the old one) — it is a de-provision plus a re-provision,
     * which is an explicit operation nobody has designed yet, not an UPDATE field.
     */
    private Mono<DomainRegistration> mergeAndUpdateDomain(DomainRegistration current,
                                                           UpdateDomainRequest req) {
        String requestedSlug = req.nsPrefix() == null ? null : req.nsPrefix().trim();
        if (requestedSlug != null && !requestedSlug.equals(current.nsPrefix())) {
            return Mono.error(ApiException.conflict(
                    "nsPrefix is immutable: domain '" + current.clusterDomain() + "' is slug '"
                            + current.nsPrefix() + "' and cannot be renamed to '" + requestedSlug
                            + "'. The slug names the tenant namespace, the ArgoCD Application "
                            + "and the Vault credential path, so a rename is a de-provision "
                            + "followed by a re-provision, not an update."));
        }
        DomainRegistration merged = new DomainRegistration(
                current.id(), current.clusterDomain(),
                req.brand() == null ? current.brand() : req.brand(),
                req.org() == null ? current.org() : req.org(),
                req.caRef() == null ? current.caRef() : req.caRef(),
                current.nsPrefix(),
                req.casdoorOrg() == null ? current.casdoorOrg() : req.casdoorOrg(),
                req.meshTag() == null ? current.meshTag() : req.meshTag(),
                req.enabled() == null ? current.enabled() : req.enabled(),
                current.createdAt(), current.createdBySubject(), current.updatedAt(),
                current.caProvisioned(), current.appsetRegistered(),
                current.lastReconciledGeneration(),
                req.idp() == null ? current.idp() : DomainIdp.normalize(req.idp()),
                current.selinuxLevel(), current.selinuxLevelPg(),
                req.brandTitle() == null ? current.brandTitle() : emptyToNull(req.brandTitle()),
                req.headscaleUrl() == null ? current.headscaleUrl() : emptyToNull(req.headscaleUrl()));
        return repo.update(merged)
                .doOnNext(saved -> log.info(
                        "[domain-registry] updated cluster_domain={} enabled={} (id={})",
                        saved.clusterDomain(), saved.enabled(), saved.id()));
    }

    /** {@code null} for a null or empty string — "not set" for the two decision-87e fields. */
    private static String emptyToNull(String value) {
        return value == null || value.isEmpty() ? null : value;
    }

    /** The first refusal among the two decision-87e fields, skipping the ones not set. */
    private static java.util.Optional<String> brandFieldRefusal(String brandTitle,
                                                                String headscaleUrl) {
        if (brandTitle != null) {
            var refusal = DomainBrandFields.titleRefusal(brandTitle);
            if (refusal.isPresent()) {
                return refusal;
            }
        }
        return headscaleUrl == null ? java.util.Optional.empty()
                : DomainBrandFields.headscaleUrlRefusal(headscaleUrl);
    }

    /**
     * SUPERADMIN "allocate now" (operator decision 89c = A, hugmesh-admin-bff-api#6 item 5) for a
     * domain registered before decision 29, whose row has no MCS pair and possibly no slug, and so
     * can never be provisioned: update refuses a slug that differs from the stored one (a NULL one
     * included) and there is no delete.
     *
     * <ul>
     *   <li>a NULL pair is allocated from {@link McsCategoryAllocator} under the same UNIQUE
     *       constraints and retry as an insert;</li>
     *   <li>a NULL slug is set ONCE from {@code requestedSlug}, validated by {@link DomainSlug}
     *       and checked for uniqueness like a create;</li>
     *   <li>a row that already has both is refused with 409 — there is nothing to allocate, and
     *       re-allocating a live row's pair would move a running workload's category;</li>
     *   <li>a slug that is already set cannot be changed here either (409): the immutability
     *       rule of {@link #update} stands.</li>
     * </ul>
     * A row holding only ONE half of a pair was hand-edited; it is refused (409) rather than
     * completed, because completing it would mean trusting a value nothing allocated.
     *
     * <p>Every successful call writes an AUDIT log line naming the actor, the domain, the slug and
     * the pair.
     */
    public Mono<DomainRegistration> allocateNow(String clusterDomain, String requestedSlug,
                                                String actor) {
        String wanted = requestedSlug == null ? null : requestedSlug.trim();
        return get(clusterDomain).flatMap(current -> allocateNowFor(current, wanted, actor));
    }

    /** The allocate-now decision for one loaded row — see {@link #allocateNow}. */
    private Mono<DomainRegistration> allocateNowFor(DomainRegistration current, String wanted,
                                                    String actor) {
        String clusterDomain = current.clusterDomain();
        boolean noLevel = isBlank(current.selinuxLevel());
        boolean noLevelPg = isBlank(current.selinuxLevelPg());
        if (noLevel != noLevelPg) {
            return Mono.<DomainRegistration>error(ApiException.conflict(
                    "domain '" + clusterDomain + "' holds half an MCS pair (selinux_level="
                            + current.selinuxLevel() + ", selinux_level_pg="
                            + current.selinuxLevelPg() + "). Nothing allocates half a pair, "
                            + "so the row was edited by hand; fix it by hand."));
        }
        boolean needsPair = noLevel;
        boolean needsSlug = isBlank(current.nsPrefix());
        if (!needsPair && !needsSlug) {
            return Mono.<DomainRegistration>error(ApiException.conflict(
                    "domain '" + clusterDomain + "' already has its slug '"
                            + current.nsPrefix() + "' and its MCS pair ("
                            + current.selinuxLevel() + ", " + current.selinuxLevelPg()
                            + "); there is nothing to allocate"));
        }
        if (!needsSlug) {
            if (wanted != null && !wanted.isEmpty() && !wanted.equals(current.nsPrefix())) {
                return Mono.<DomainRegistration>error(ApiException.conflict(
                        "nsPrefix is immutable: domain '" + clusterDomain + "' is slug '"
                                + current.nsPrefix() + "' and cannot be renamed to '"
                                + wanted + "'. Allocate-now only sets a slug that is missing."));
            }
            return allocate(current, current.nsPrefix(), actor);
        }
        var slugRefusal = DomainSlug.refusalReason(wanted);
        if (slugRefusal.isPresent()) {
            return Mono.<DomainRegistration>error(ApiException.badRequest(
                    "domain '" + clusterDomain + "' has no slug yet, so allocate-now needs "
                            + "one: " + slugRefusal.get()));
        }
        return repo.findByNsPrefix(wanted)
                .flatMap(clash -> Mono.<DomainRegistration>error(ApiException.conflict(
                        "slug '" + wanted + "' is already used by domain '"
                                + clash.clusterDomain() + "'; it names the Vault path "
                                + DomainSlug.vaultPath(wanted) + " and cannot be shared")))
                .switchIfEmpty(Mono.defer(() -> allocate(current, wanted, actor)));
    }

    /** The allocate-now write itself, with its refusals mapped to clean 409s and its audit line. */
    private Mono<DomainRegistration> allocate(DomainRegistration current, String slug,
                                              String actor) {
        return repo.allocateNow(current, slug)
                .switchIfEmpty(Mono.error(ApiException.conflict(
                        "domain '" + current.clusterDomain() + "' was changed while its slug or "
                                + "MCS pair was being allocated; re-read it and retry")))
                .onErrorMap(McsCategoryAllocator.Exhausted.class,
                        ex -> ApiException.conflict(ex.getMessage()))
                .onErrorMap(DomainSlug::isSlugCollision, ex -> ApiException.conflict(
                        "slug '" + slug + "' was registered by another domain concurrently; it "
                                + "names the Vault path " + DomainSlug.vaultPath(slug)
                                + " and cannot be shared"))
                .doOnNext(saved -> log.warn("[domain-registry] AUDIT allocate-now actor={} "
                                + "cluster_domain={} slug={} (was {}) selinux_level={} "
                                + "selinux_level_pg={} (was {}/{})",
                        actor, saved.clusterDomain(), saved.nsPrefix(), current.nsPrefix(),
                        saved.selinuxLevel(), saved.selinuxLevelPg(),
                        current.selinuxLevel(), current.selinuxLevelPg()));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * A node agent's reconcile ACK (decision 89b; hugmesh-generator
     * {@code specs/usr/sbin/hugmesh-domain-reconcile:ack_generation}). Advances
     * {@code appset_registered} and {@code last_reconciled_generation} only when the reported
     * generation is newer than the stored one; {@code ca_provisioned} is never written here
     * (decision 87a = B). Emits {@code true} when the ack advanced the row, {@code false} when it
     * was stale; a 404 for a domain that is not registered.
     */
    public Mono<Boolean> recordReconcileAck(String clusterDomain, boolean appsetRegistered,
                                            long generation) {
        return repo.recordReconcileAck(clusterDomain, appsetRegistered, generation)
                .flatMap(updated -> updated == 1L ? Mono.just(Boolean.TRUE)
                        // 0 rows: stale generation OR unknown domain — only a read can tell.
                        : get(clusterDomain).map(existing -> Boolean.FALSE));
    }

    /**
     * Best-effort, idempotent {@code @system} provisioning for a freshly created domain.
     * A no-op when no provisioner is wired (the back-compat unit constructor) or when the
     * SHIPS-DARK gate is closed; a Casdoor failure is logged + swallowed so the registered
     * domain row is never lost (a SUPERADMIN can re-provision via the system-account
     * endpoint).
     */
    private Mono<Void> provisionSystemAccount(String clusterDomain) {
        if (systemAccount == null) return Mono.empty();
        return systemAccount.provision(clusterDomain)
                .onErrorResume(e -> {
                    log.warn("[domain-registry] best-effort @system provision for '{}' failed "
                            + "(domain row kept; re-provision later): {}", clusterDomain, e.toString());
                    return Mono.empty();
                });
    }
}
