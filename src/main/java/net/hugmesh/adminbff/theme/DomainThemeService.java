package net.hugmesh.adminbff.theme;

import net.hugmesh.commons.security.PrincipalDomain;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Who may theme which domain.
 *
 * THE AUTHORIZATION RULE, and it is enforced HERE rather than by which controls a UI
 * renders: a SUPERADMIN may read and set any domain's theme including the mesh default;
 * a domain ADMIN may read and set ONLY their own. Hiding the control in admin-ui is
 * courtesy, not security — the request still reaches this service, and this is the layer
 * that has to say no. That distinction is not theoretical on this platform: the host
 * shell's menu and the gateway read DIFFERENT sources of role truth, and an operator
 * hit exactly that split when the menu offered Moderation while the gateway refused it.
 *
 * FAIL CLOSED. A null scope resolves to {@link PrincipalDomain#NO_DOMAIN}, which as a
 * TARGET means the mesh default and as an ACTOR matches nothing — so an unauthenticated
 * or unscoped caller can neither read another domain's theme nor write any. The same
 * sentinel therefore has to be read carefully in both positions, which is why the
 * actor's scope and the target domain are separate parameters everywhere below rather
 * than one conflated "domain".
 */
@Service
public class DomainThemeService {

    private final DomainThemeRepository repo;

    public DomainThemeService(DomainThemeRepository repo) {
        this.repo = repo;
    }

    /** Every theme the caller may SEE: all of them for a superadmin, otherwise just
     *  their own domain's (plus the mesh default, which every domain inherits and so
     *  every admin has a legitimate need to read). */
    public Flux<DomainTheme> list(PrincipalDomain scope) {
        if (isSuperadmin(scope)) {
            return repo.findAll();
        }
        String own = actingDomain(scope);
        if (own.isEmpty()) {
            // Unresolvable actor: it may still read the default it would inherit, but it
            // has no "own domain" whose row it could be shown.
            return repo.findByDomain(DomainTheme.MESH_DEFAULT).flux();
        }
        return repo.findByDomain(own)
                .concatWith(repo.findByDomain(DomainTheme.MESH_DEFAULT))
                .distinct(DomainTheme::domain);
    }

    /** The theme that APPLIES to {@code domain}: its own row, else the mesh default.
     *
     *  Deliberately unauthorized — this is the RESOLUTION used to render a page, and a
     *  visitor who is not signed in at all still has to receive the right colours. It
     *  exposes no more than the domain's own public appearance. */
    public Mono<DomainTheme> resolve(String domain) {
        String d = DomainTheme.normalizeDomain(domain);
        Mono<DomainTheme> fallback = repo.findByDomain(DomainTheme.MESH_DEFAULT)
                .switchIfEmpty(Mono.just(meshFallback()));
        // Asking for the default IS the fallback — going through findByDomain twice for
        // the same key would be a wasted round trip on the unauthenticated render path.
        return d.equals(DomainTheme.MESH_DEFAULT)
                ? fallback
                : repo.findByDomain(d).switchIfEmpty(fallback);
    }

    /** Set one domain's theme. Refuses unless the caller may manage that domain. */
    public Mono<DomainTheme> set(DomainTheme theme, PrincipalDomain scope, String actor) {
        String target = theme.domain();
        if (!canManage(scope, target)) {
            // 403, not 404: the domain's existence is not the secret here, the right to
            // change it is. A 404 would also be a lie the caller could disprove by
            // loading the domain's own login page.
            return Mono.error(new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "not permitted to set the theme for domain '" + target + "'"));
        }
        return repo.upsert(new DomainTheme(
                target, theme.preset(), theme.ramp(), theme.style(),
                theme.primaryHex(), theme.secondaryHex(), actor));
    }

    /** Clear a domain's override so it inherits the mesh default again. */
    public Mono<Void> clear(String domain, PrincipalDomain scope) {
        if (!canManage(scope, domain)) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "not permitted to clear the theme for domain '" + domain + "'"));
        }
        return repo.delete(domain);
    }

    /**
     * May {@code scope} manage {@code target}?
     *
     * Superadmin: anything, including the mesh default (that is what distinguishes the
     * role — the default is every domain's inheritance, so setting it is a mesh-wide act).
     * Domain admin: their own domain ONLY, and explicitly NOT the mesh default, because
     * changing it would repaint every domain that has not overridden it.
     */
    public boolean canManage(PrincipalDomain scope, String target) {
        if (isSuperadmin(scope)) {
            return true;
        }
        String own = actingDomain(scope);
        if (own.isEmpty()) {
            return false;            // unresolvable actor: fail closed
        }
        // Through the same normalisation the row is KEYED by, so a caller cannot reach a
        // row by spelling its domain differently than the write path would have.
        String t = DomainTheme.normalizeDomain(target);
        return !t.equals(DomainTheme.MESH_DEFAULT) && t.equals(own);
    }

    private static boolean isSuperadmin(PrincipalDomain scope) {
        return scope != null && !scope.scoped();
    }

    /**
     * The acting domain, with null/blank AND the {@link PrincipalDomain#NO_DOMAIN}
     * sentinel all collapsed to "no domain at all" — an actor with no resolvable domain
     * must match NOTHING.
     *
     * <p>This deliberately does NOT use {@link DomainTheme#normalizeDomain}: that maps
     * the same inputs to the mesh default, which is correct for a target and catastrophic
     * for an actor. Reading NO_DOMAIN as a domain name is precisely the bug this replaces
     * — {@code " no-domain".trim()} is {@code "no-domain"}, a non-empty string that
     * sailed past the fail-closed check and then matched the mesh default's own key, so a
     * principal whose tenant could not be resolved could repaint every domain on the mesh.
     */
    private static String actingDomain(PrincipalDomain scope) {
        if (scope == null) {
            return "";
        }
        String d = scope.domain();
        if (d == null) {
            return "";
        }
        d = d.trim();
        return d.equals(PrincipalDomain.NO_DOMAIN.trim()) ? "" : d;
    }

    /** What a mesh with no rows at all renders: the shipped brand on the dark ramp. */
    static DomainTheme meshFallback() {
        return new DomainTheme(DomainTheme.MESH_DEFAULT, "dark",
                DomainTheme.DEFAULT_RAMP, DomainTheme.DEFAULT_STYLE, null, null, null);
    }
}
