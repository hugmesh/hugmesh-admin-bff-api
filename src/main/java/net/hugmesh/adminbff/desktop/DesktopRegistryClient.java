package net.hugmesh.adminbff.desktop;

import reactor.core.publisher.Mono;

/**
 * The seam to the UPSTREAM Flatpak/OCI registry the Plasma Discover store proxies — the
 * filtering reverse-proxy/index fetches an allowlisted ref's index/manifest from upstream
 * (Flathub-OCI). SHIPS DARK by default: the {@link NoopDesktopRegistryClient} logs the
 * would-be fetch and returns a placeholder without dialing any upstream, so the FILTERING +
 * authz around it are fully exercisable (and a ships-dark test can assert
 * {@code isReal() == false}) without a live registry.
 *
 * <p>Wired by {@link DesktopRegistryConfig}: ONE flag
 * ({@code app.desktop.registry.enabled}, default false) selects the Noop (dark) vs the
 * real client, exactly like the App-Store {@code ArgoCdConfig}.
 */
public interface DesktopRegistryClient {

    /**
     * Fetch the upstream index/manifest bytes for one allowlisted ref. The caller has
     * ALREADY proven the ref is in the requesting domain's ENABLED allowlist — this only
     * proxies the bytes. Returns a small JSON descriptor (the index location) the desktop
     * Discover backend consumes.
     */
    Mono<String> fetchRefIndex(String appRef, String source);

    /** Whether this is the REAL upstream client (true) or the ships-dark Noop (false). */
    boolean isReal();
}
