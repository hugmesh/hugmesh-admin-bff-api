package systems.hugmesh.adminbff.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * PROD-PROFILE startup guard for the SHARED INTERNAL-SERVICE CREDENTIAL that gates the
 * {@code /bff/internal/**} subtree. The SIBLING of auth-core's {@code InternalSurfaceBootGuard}
 * (which asserts the mTLS half of the same boundary) and deliberately written in its idiom:
 * wired ONLY under {@code @Profile("!dev & !test")} — the same predicate as the production
 * {@link SecurityConfig#filterChain} — and FAILING FAST during context refresh rather than
 * serving that surface unprotected.
 *
 * <h3>Why the credential cannot be optional</h3>
 * {@link SecurityConfig} gates {@code /bff/internal/**} on {@code ROLE_SERVICE}, and the
 * principal every real caller presents is the {@code X-Internal-Token} promoted by
 * {@code SecurityConfig#internalServiceTokenAuthFilter()}. Consistent with auth-core's
 * {@code InternalTokenWebFilter}, a BLANK {@code app.internal.token} means UNARMED — the
 * historic permitAll behaviour, which local/dev/CI runs still rely on (the compose stack ships
 * with {@code INTERNAL_TOKEN} unset). That degradation is only ever acceptable off-cluster,
 * because the subtree is NOT in fact unreachable from outside:
 *
 * <ul>
 *   <li>the fe-gateway's terminal route is {@code path: /bff/**} → admin-bff, and NO
 *       more-specific route and NO {@code gateway_route_access} row covers
 *       {@code /bff/internal/**} — the route-access filter resolves NO_RULE ⇒ FORWARD;</li>
 *   <li>mTLS does not distinguish that traffic: the gateway presents its own cluster-CA client
 *       cert on the proxy leg, so the handshake succeeds on the caller's behalf.</li>
 * </ul>
 *
 * So an unarmed PRODUCTION instance exposes account creation, session MINTING for any
 * accountId, the live-session listing and the custody-JWT exchange to any authenticated user
 * of any brand. Refusing to boot is the only honest outcome: a missing credential is a
 * deployment error, never a degraded mode.
 *
 * <p>Complete NO-OP in dev/test (the bean is never created there), so local/CI runs are
 * unaffected. In-cluster, {@code INTERNAL_TOKEN} is injected from the ESO-synced
 * {@code bff-internal-token} Secret that the gateways / user-bff / mod-bff already mount to
 * SEND the same header.
 */
@Component
@Profile("!dev & !test")
public class InternalSurfaceTokenBootGuard implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(InternalSurfaceTokenBootGuard.class);

    private final String internalToken;

    public InternalSurfaceTokenBootGuard(@Value("${app.internal.token:}") String internalToken) {
        this.internalToken = internalToken == null ? "" : internalToken;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (internalToken.isBlank()) {
            throw new IllegalStateException(
                    "REFUSING TO BOOT: the privilege-bearing /bff/internal/** surface "
                    + "(session MINTING for any account, custody-JWT exchange, account "
                    + "create/complete) is gated on ROLE_SERVICE, and in production the only "
                    + "principal its in-cluster callers present is the shared internal-service "
                    + "credential — but app.internal.token is blank, which would degrade the "
                    + "whole subtree to the legacy unauthenticated behaviour while the "
                    + "fe-gateway's /bff/** route still reaches it. Inject INTERNAL_TOKEN (the "
                    + "bff-internal-token Secret the gateways and user-bff already mount), or "
                    + "run with the dev/test profile.");
        }
        // Never log the credential itself — only that the surface is armed.
        log.info("[internal-surface-token-guard] /bff/internal/** internal-service credential "
                + "configured — boot OK");
    }
}
