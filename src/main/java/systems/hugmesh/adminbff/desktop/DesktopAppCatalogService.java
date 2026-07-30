package systems.hugmesh.adminbff.desktop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;

/**
 * Write/read surface for {@code desktop_app_catalog} — the per-domain Plasma Discover
 * allowlist. ADMIN/SUPERADMIN curate (add / enable / disable / remove); the domain a row
 * lands in is the CALLER'S brand (from the validated issuer via {@link PrincipalDomain}), never
 * caller-supplied.
 *
 * <h3>add != enable (DEFAULT-NONE)</h3>
 * {@link #add} writes the row with {@code enabled = false}. A separate {@link #setEnabled}
 * call flips it. So a brand whose admin has only ADDED apps still serves an EMPTY Discover
 * store until apps are explicitly enabled — the store is default-NONE.
 */
@Service
public class DesktopAppCatalogService {

    private static final Logger log = LoggerFactory.getLogger(DesktopAppCatalogService.class);

    private final DesktopAppCatalogRepository repo;

    public DesktopAppCatalogService(DesktopAppCatalogRepository repo) {
        this.repo = repo;
    }

    /** The catalog VISIBLE to the acting principal — own brand (scoped admin) or all
     *  (superadmin). */
    public Flux<DesktopAppCatalogEntry> list(PrincipalDomain scope) {
        return repo.list(scope);
    }

    /**
     * Idempotently ADD an app ref to the caller's brand catalog (DISABLED — add != enable).
     * The {@code domain} is the caller's brand (NEVER the request); a SUPERADMIN supplies
     * the explicit target domain via the path (resolved by the controller into the scope's
     * home domain). An existing (domain, appRef) row is returned unchanged (the no-op add).
     */
    public Mono<DesktopAppCatalogEntry> add(String domain, String appRef, String displayName,
                                            String source, String addedBy) {
        String src = normalizeSource(source);
        return repo.findByDomainAndRef(domain, appRef)
                .doOnNext(existing -> log.info(
                        "[desktop-catalog] {} already in {} catalog (id={}) — no-op", appRef, domain, existing.id()))
                .switchIfEmpty(Mono.defer(() -> repo.insert(domain, appRef, displayName, src, addedBy)
                        .doOnNext(e -> log.info(
                                "[desktop-catalog] added {} to {} catalog DISABLED (default-NONE) id={}",
                                appRef, domain, e.id()))));
    }

    /** Enable / disable a catalog row (SCOPED). Returns rows-updated (0 = absent / out of
     *  scope). Flipping enabled is the ONLY thing that makes a ref appear in Discover. */
    public Mono<Long> setEnabled(String id, boolean enabled, PrincipalDomain scope) {
        return repo.setEnabled(id, enabled, scope)
                .doOnNext(n -> log.info("[desktop-catalog] setEnabled id={} -> {} rows={}", id, enabled, n));
    }

    /** Remove a catalog row (SCOPED). Returns rows-updated. */
    public Mono<Long> remove(String id, PrincipalDomain scope) {
        return repo.delete(id, scope)
                .doOnNext(n -> log.info("[desktop-catalog] remove id={} rows={}", id, n));
    }

    private static String normalizeSource(String source) {
        if (source == null || source.isBlank()) return DesktopAppCatalogEntry.SOURCE_FLATPAK;
        String s = source.trim().toUpperCase();
        return DesktopAppCatalogEntry.SOURCE_OCI.equals(s)
                ? DesktopAppCatalogEntry.SOURCE_OCI : DesktopAppCatalogEntry.SOURCE_FLATPAK;
    }
}
