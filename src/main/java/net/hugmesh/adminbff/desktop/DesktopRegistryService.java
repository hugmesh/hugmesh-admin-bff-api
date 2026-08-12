package net.hugmesh.adminbff.desktop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * The discover-registry FILTERING + authz core — the load-bearing security boundary the
 * Plasma Discover store hits. The {@code discover} role gates the controller; THIS service
 * enforces the DOMAIN-LOCK + the ENABLED-ONLY allowlist:
 *
 * <ul>
 *   <li>{@link #listEnabled(String)} serves ONLY the caller's-domain ENABLED refs (the
 *       domain is the caller's brand from the validated issuer, resolved by the controller —
 *       NEVER a request field). An empty / all-disabled catalog serves NOTHING.</li>
 *   <li>{@link #fetchRef(String, String)} resolves a SINGLE ref ONLY if it is in THIS
 *       domain's enabled allowlist; a ref that is disabled, absent, or belongs to ANOTHER
 *       brand yields {@link Mono#empty()} — the controller maps that to 404 (deny, no
 *       cross-domain leak). The upstream fetch ({@link DesktopRegistryClient}) is reached
 *       ONLY after that gate passes, and ships DARK behind the Noop by default.</li>
 * </ul>
 *
 * This is REAL + tested. The upstream PROXY is what ships dark; the filtering + authz do not.
 */
@Service
public class DesktopRegistryService {

    private static final Logger log = LoggerFactory.getLogger(DesktopRegistryService.class);

    private final DesktopAppCatalogRepository catalog;
    private final DesktopRegistryClient upstream;

    public DesktopRegistryService(DesktopAppCatalogRepository catalog, DesktopRegistryClient upstream) {
        this.catalog = catalog;
        this.upstream = upstream;
    }

    /** The ENABLED refs visible to ONE domain (the Discover index). Domain-locked +
     *  enabled-only; empty for a brand with no enabled apps. */
    public Flux<DesktopAppCatalogEntry> listEnabled(String domain) {
        return catalog.listEnabledForDomain(domain);
    }

    /**
     * Resolve + proxy ONE ref's upstream index — ONLY if {@code appRef} is in
     * {@code domain}'s ENABLED allowlist. The catalog gate runs FIRST (domain-lock +
     * enabled), so a not-in-allowlist ref never reaches the upstream client (which ships
     * dark anyway). Empty when the gate denies — the controller returns 404 (no leak).
     */
    public Mono<String> fetchRef(String domain, String appRef) {
        return catalog.findEnabledByRef(domain, appRef)
                .flatMap(entry -> {
                    log.debug("[desktop-registry] domain={} ref={} authorized (enabled allowlist); "
                            + "upstream real={}", domain, appRef, upstream.isReal());
                    return upstream.fetchRefIndex(entry.appRef(), entry.source());
                })
                .doOnSuccess(r -> {
                    if (r == null) {
                        log.debug("[desktop-registry] DENY domain={} ref={} (not in enabled allowlist)",
                                domain, appRef);
                    }
                });
    }

    /** Whether the upstream registry proxy is REAL (true) or ships dark (false). Surfaced so
     *  a ships-dark test can assert the default-dark posture structurally. */
    public boolean upstreamIsReal() {
        return upstream.isReal();
    }
}
