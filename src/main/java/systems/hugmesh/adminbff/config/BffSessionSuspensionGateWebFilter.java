package systems.hugmesh.adminbff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import systems.hugmesh.adminbff.suspension.SuspensionService;
import systems.hugmesh.authcore.account.AccountStatus;

import java.util.Optional;

/**
 * Suspension/ban gate for a native-login ({@code bff_}) session on admin-bff's OWN surface.
 *
 * <p>admin-bff authenticates a {@code bff_} session LOCALLY via the shared auth-core
 * {@code BffCookieAuthenticationWebFilter} (@Order HIGHEST_PRECEDENCE+10), which resolves the
 * session against {@code AccountStore} and grants authorities from {@code account.roles()} —
 * but that shared filter does NOT re-check suspension status. Its two SIBLINGS do: mod-bff's
 * and user-bff's own bff_ auth filters hard-403 a {@code suspended}/{@code banned} session
 * (the platform's "each service independently re-authenticates the bff_ — it must not assume
 * the gateway authorized it" invariant). A ban writes only an {@code access_suspension} row —
 * it never deletes the {@code bff_session} row and never rewrites the {@code account.roles}
 * CSV (that is login-only via {@code ensureAccount}) — so a still-valid PRE-ban session keeps
 * its full role set. The gateway's own introspect/exchange gate blocks a suspended session at
 * the front door, but a request that reaches admin-bff BYPASSING the gateway (in-mesh
 * pod-to-pod with a raw {@code bff_} cookie) hit ONLY the shared filter, which failed open —
 * exactly the threat the sibling filters exist to defend against. This restores parity.
 *
 * <p>Runs at {@code HIGHEST_PRECEDENCE+11}, immediately after the shared bridge, so the
 * bff_-derived {@link Authentication} is already in the Reactor security context. It gates
 * ONLY the {@code bff_} carrier (a {@code String}-principal auth = {@code account.id()}); a
 * real Casdoor JWT (a {@code Jwt} principal, authenticated later in the security chain, so
 * absent from the context here) is untouched. Fail-safe: a non-account {@code String}
 * principal resolves via {@link SuspensionService#statusFor} to {@code active} (no rows) and
 * passes through.
 *
 * <p>The chain is invoked from EXACTLY ONE arm (branch on an {@link Optional} first) — a
 * {@code flatMap(...chain.filter...).switchIfEmpty(chain.filter)} would double-execute the
 * downstream on every request, since {@code chain.filter()} returns a never-onNext
 * {@code Mono<Void>} (the same trap the shared filter's own class doc calls out).
 *
 * <p>{@link SuspensionService} is taken as an {@link ObjectProvider} (not a hard ctor dep),
 * mirroring the auth-core filter's {@code AccountStore} handling: this {@code WebFilter} is
 * auto-included in every {@code @WebFluxTest} slice, but such slices don't wire the
 * {@code @Service}, so a hard dependency would fail their context. Absent provider ⇒ pass
 * through (identical to pre-filter behaviour).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 11)
public class BffSessionSuspensionGateWebFilter implements WebFilter {

    private final ObjectProvider<SuspensionService> suspensions;

    public BffSessionSuspensionGateWebFilter(ObjectProvider<SuspensionService> suspensions) {
        this.suspensions = suspensions;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        SuspensionService svc = suspensions.getIfAvailable();
        if (svc == null) {
            return chain.filter(exchange);
        }
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> bffHandle(ctx.getAuthentication()))
                .defaultIfEmpty(Optional.empty())
                .flatMap(handle -> handle.isEmpty()
                        ? chain.filter(exchange)
                        : svc.statusFor(handle.get())
                                .flatMap(status -> isDenied(status)
                                        ? reject(exchange, status)
                                        : chain.filter(exchange)));
    }

    /** The account handle for a bff_-derived auth, else empty (JWT / unauthenticated /
     *  non-String principal). The principal is {@code account.id()} = {@code provider:handle};
     *  the handle is the segment after the first {@code ':'}. */
    private static Optional<String> bffHandle(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) return Optional.empty();
        if (!(auth.getPrincipal() instanceof String id) || id.isBlank()) return Optional.empty();
        int sep = id.indexOf(':');
        return Optional.of(sep >= 0 && sep + 1 < id.length() ? id.substring(sep + 1) : id);
    }

    private static boolean isDenied(AccountStatus status) {
        String s = status == null ? null : status.status();
        return AccountStatus.SUSPENDED.equals(s) || AccountStatus.BANNED.equals(s);
    }

    private Mono<Void> reject(ServerWebExchange exchange, AccountStatus status) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().add("X-Bff-Denied", "account-" + status.status());
        return exchange.getResponse().setComplete();
    }
}
