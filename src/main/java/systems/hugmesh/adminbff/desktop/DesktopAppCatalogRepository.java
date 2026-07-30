package systems.hugmesh.adminbff.desktop;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code desktop_app_catalog} — the per-domain Plasma Discover
 * allowlist (schema in Liquibase {@code db/changelog/140-desktop-app-governance.xml}).
 * App-generated UUID ids and the verified {@code scope == null || scope.scoped() ?
 * WHERE domain=:domain : unscoped} branch.
 *
 * <p>Backed by the Spring Data {@link DesktopAppCatalogR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link DesktopAppCatalogRow} entity to/from the
 * {@link DesktopAppCatalogEntry} domain record.
 *
 * <p>The discover-registry read is DELIBERATELY narrow: {@link #listEnabledForDomain} /
 * {@link #findEnabledByRef} filter on BOTH {@code domain} AND {@code enabled = true}, so a
 * ref that is not in the CALLER'S domain's enabled allowlist is invisible — there is no
 * cross-domain leak and a disabled ref serves nothing (fail-closed).
 */
@Repository
public class DesktopAppCatalogRepository {

    private final DesktopAppCatalogR2dbcRepository repo;

    public DesktopAppCatalogRepository(DesktopAppCatalogR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── catalog CRUD (admin/superadmin) ─────────────────────────────────────────

    /** ALL catalog rows VISIBLE to the given tenant scope — the ADMIN curation read. A
     *  scoped admin sees ONLY their brand's rows; SUPERADMIN (unscoped) sees all. */
    public Flux<DesktopAppCatalogEntry> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByDisplayName(domain).map(DesktopAppCatalogRow::toDomain);
        }
        return repo.findByOrderByDomainAscDisplayNameAsc().map(DesktopAppCatalogRow::toDomain);
    }

    /** The active row for (domain, appRef), if any — the idempotency / conflict check on
     *  add. UNSCOPED by id args (the service has already resolved the domain). */
    public Mono<DesktopAppCatalogEntry> findByDomainAndRef(String domain, String appRef) {
        return repo.findByDomainAndAppRef(domain, appRef).map(DesktopAppCatalogRow::toDomain);
    }

    /** A single row by id, scoped (a scoped admin cannot resolve another brand's row). */
    public Mono<DesktopAppCatalogEntry> findById(String id, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByIdAndDomain(id, domain).map(DesktopAppCatalogRow::toDomain);
        }
        return repo.findById(id).map(DesktopAppCatalogRow::toDomain);
    }

    /** Insert a new catalog row (app-generated id) in {@code domain}, ENABLED FALSE
     *  (default-NONE — add != enable), returning it. */
    public Mono<DesktopAppCatalogEntry> insert(String domain, String appRef, String displayName,
                                               String source, String addedBy) {
        Instant createdAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200) and the not-yet-set updated_at (default NULL); RETURNING id hands back the generated
        // string, mapped into the persisted entry with the SAME field order/values (enabled FALSE).
        return repo.insertReturningId(appRef, displayName, source, false, addedBy, domain, createdAt)
                .map(genId -> new DesktopAppCatalogEntry(genId, appRef, displayName, source, false,
                        addedBy, domain, createdAt, null));
    }

    /** Flip {@code enabled} for one row id, SCOPED so a scoped admin can only mutate their
     *  own brand's row. Returns the rows-updated count (0 = absent / out of scope). */
    public Mono<Long> setEnabled(String id, boolean enabled, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.setEnabledScoped(id, enabled, domain);
        }
        return repo.setEnabledAll(id, enabled);
    }

    /** Remove a row by id, SCOPED (a scoped admin can only delete their own brand's row).
     *  Returns the rows-updated count. */
    public Mono<Long> delete(String id, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.deleteScoped(id, domain);
        }
        return repo.deleteByIdReturningCount(id);
    }

    // ── registry read (discover-role; domain-locked; enabled-only) ──────────────

    /** The ENABLED refs for ONE domain — the discover registry working set. Only
     *  {@code enabled = true} rows for {@code domain}; a disabled / absent ref is never
     *  returned (fail-closed, no cross-domain leak). */
    public Flux<DesktopAppCatalogEntry> listEnabledForDomain(String domain) {
        return repo.findByDomainAndEnabledTrueOrderByDisplayName(domain)
                .map(DesktopAppCatalogRow::toDomain);
    }

    /** Resolve ONE enabled ref for a domain (the registry single-ref fetch authz gate).
     *  Empty when the ref is not in THIS domain's enabled allowlist (disabled / absent /
     *  another brand's) — the caller fails closed (404). */
    public Mono<DesktopAppCatalogEntry> findEnabledByRef(String domain, String appRef) {
        return repo.findByDomainAndAppRefAndEnabledTrue(domain, appRef)
                .map(DesktopAppCatalogRow::toDomain);
    }
}
