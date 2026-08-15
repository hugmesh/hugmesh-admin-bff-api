package net.hugmesh.adminbff.desktop;

import reactor.core.publisher.Mono;

/**
 * The seam that pushes one {@code desktop_sudo_grant} row's desired state to the IdP —
 * membership on the generator-seeded {@code desktop-sudo} Casdoor role (casdoor-init seeds it
 * with {@code users: []}; this seam is what actually populates it, so a grant reaches the
 * user's {@code roles} claim). Without this leg a grant is a DB row the IdP never learns
 * about and the claim is never minted.
 *
 * <p>SHIPS DARK by default: the {@link NoopDesktopSudoClaimSync} performs NO IdP write and
 * reports the row's propagation honestly still {@code pending}, so a dev/test/CI run dials
 * nothing and the UI never claims a propagation that did not happen. Wired by
 * {@link DesktopSudoClaimSyncConfig}: ONE flag ({@code app.desktop.sudo.claim-sync.enabled},
 * default false) selects Noop vs the real {@link CasdoorDesktopSudoClaimSync}.
 */
public interface DesktopSudoClaimSync {

    /**
     * Push {@code grant}'s desired state to the IdP: an ACTIVE grant adds the subject to the
     * {@code desktop-sudo} role; a REVOKED grant removes it UNLESS the subject still holds
     * another active grant (the role is per-subject; the per-device wall is the entitlement
     * read). Returns the resulting {@link DesktopSudoGrant#propagationState()} value —
     * {@code applied} on success, {@code failed} on an IdP error (the worker retries), and
     * {@code pending} when the leg is dark (Noop / Casdoor admin client absent). NEVER errors.
     */
    Mono<String> propagate(DesktopSudoGrant grant);

    /** Whether this is the REAL Casdoor-writing sync (true) or the ships-dark Noop (false). */
    boolean isReal();
}
