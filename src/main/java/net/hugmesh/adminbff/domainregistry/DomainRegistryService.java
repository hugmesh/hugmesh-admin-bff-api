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
        DomainRegistration draft = new DomainRegistration(
                null, clusterDomain, req.brand(), req.org(), req.caRef(), req.nsPrefix().trim(),
                req.casdoorOrg(), req.meshTag(),
                !Boolean.FALSE.equals(req.enabled()),
                null, createdBySubject, null, false, false, 0L,
                DomainIdp.normalize(req.idp()), null, null);
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
                current.selinuxLevel(), current.selinuxLevelPg());
        return repo.update(merged)
                .doOnNext(saved -> log.info(
                        "[domain-registry] updated cluster_domain={} enabled={} (id={})",
                        saved.clusterDomain(), saved.enabled(), saved.id()));
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
