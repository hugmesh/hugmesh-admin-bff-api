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
        return repo.findByDomain(own)
                .concatWith(repo.findByDomain(PrincipalDomain.NO_DOMAIN))
                .distinct(DomainTheme::domain);
    }

    /** The theme that APPLIES to {@code domain}: its own row, else the mesh default.
     *
     *  Deliberately unauthorized — this is the RESOLUTION used to render a page, and a
     *  visitor who is not signed in at all still has to receive the right colours. It
     *  exposes no more than the domain's own public appearance. */
    public Mono<DomainTheme> resolve(String domain) {
        String d = domain == null ? "" : domain.trim();
        return repo.findByDomain(d)
                .switchIfEmpty(repo.findByDomain(PrincipalDomain.NO_DOMAIN))
                .switchIfEmpty(Mono.just(meshFallback()));
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
            return false;            // unscoped actor: fail closed
        }
        String t = target == null ? "" : target.trim();
        return !t.isEmpty() && t.equals(own);
    }

    private static boolean isSuperadmin(PrincipalDomain scope) {
        return scope != null && !scope.scoped();
    }

    /** The acting domain, with the null/blank cases collapsed to "no domain at all"
     *  rather than to the mesh default — an actor with no domain must match nothing. */
    private static String actingDomain(PrincipalDomain scope) {
        if (scope == null) {
            return "";
        }
        String d = scope.domain();
        return d == null ? "" : d.trim();
    }

    /** What a mesh with no rows at all renders: the shipped brand on the dark ramp. */
    static DomainTheme meshFallback() {
        return new DomainTheme(PrincipalDomain.NO_DOMAIN, "dark",
                DomainTheme.DEFAULT_RAMP, DomainTheme.DEFAULT_STYLE, null, null, null);
    }
}
