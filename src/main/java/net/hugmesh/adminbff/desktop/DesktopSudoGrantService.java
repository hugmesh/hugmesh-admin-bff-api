package net.hugmesh.adminbff.desktop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.SshLicense;
import net.hugmesh.adminbff.device.SshLicenseRepository;
import net.hugmesh.commons.security.PrincipalDomain;

/**
 * Write/read surface for {@code desktop_sudo_grant} — the SSO-enforced sudo grants.
 * ADMIN/SUPERADMIN issue/revoke; the desired-state pattern mirrors
 * {@link net.hugmesh.adminbff.device.SshLicenseService}: an idempotent grant
 * (findActive-then-insert) + a CAS revoke that NEVER deletes (the row is the audit trail).
 * Every mutate bumps the monotonic {@code generation}.
 *
 * <h3>DEFAULT NONE</h3>
 * Absent an active grant, the subject has NO sudo on the device — the entitlement read
 * ({@link #entitlement}) returns empty, so the IdP/desktop mints no claim. A grant confers
 * sudo by adding the claim; a revoke removes it at the next refresh (centrally revocable).
 *
 * <h3>residency-stamped domain</h3>
 * {@code grant.domain} is stamped from the RESOLVED device's residency (never caller-
 * supplied), so a grant can never claim a different brand than the device it targets.
 *
 * <h3>IdP claim propagation ({@link DesktopSudoClaimSync})</h3>
 * The DB row is the desired state; what actually reaches the {@code roles} claim is
 * membership on the generator-seeded {@code desktop-sudo} Casdoor role. Every mutate arms
 * {@code propagation_state='pending'}, is pushed inline through the claim-sync seam
 * (best-effort — a push failure NEVER fails the grant/revoke, the row is already
 * authoritative), and the {@link DesktopSudoClaimReconciler} sweep retries whatever stayed
 * {@code pending}/{@code failed}. Ships dark: with
 * {@code app.desktop.sudo.claim-sync.enabled=false} (the default) the seam is the Noop and
 * rows honestly stay {@code pending}.
 *
 * <h3>Revocation vs live sessions — HONEST semantics</h3>
 * Revocation follows the platform's role-change model ({@code AdminController.revokeRole}):
 * it takes effect at the NEXT token refresh/login — there is NO desktop session-kill
 * anywhere in the platform, so a desktop session already holding a sudo-bearing token keeps
 * it until that token expires (and the on-device PAM/polkit re-consults the claim at its
 * next evaluation). Two things bound the stale window: (1) the entitlement read above denies
 * the device the moment the row flips (an IdP/desktop that re-checks per privileged action
 * sees the revoke immediately), and (2) the claim-sync leg posts a best-effort
 * {@code subject:<subject>} gateway revocation (same as every direct role revoke) so a live
 * WEB custody JWT is denied at the gateway rather than riding out its ~1 h TTL.
 */
@Service
public class DesktopSudoGrantService {

    private static final Logger log = LoggerFactory.getLogger(DesktopSudoGrantService.class);

    private final DesktopSudoGrantRepository repo;
    private final DeviceRegistryRepository devices;
    private final SshLicenseRepository licenses;
    private final DesktopSudoClaimSync claimSync;

    public DesktopSudoGrantService(DesktopSudoGrantRepository repo, DeviceRegistryRepository devices,
                                   SshLicenseRepository licenses, DesktopSudoClaimSync claimSync) {
        this.repo = repo;
        this.devices = devices;
        this.licenses = licenses;
        this.claimSync = claimSync;
    }

    /**
     * Idempotently grant {@code subject} sudo on {@code deviceId}. The device is resolved
     * FIRST so the grant.domain is stamped from its residency, and a SUPERADMIN-owned
     * (core/primary) device is REJECTED (sudo on a core node is governed by mesh-membership,
     * not a per-user desktop grant — same idiom as the SSH license). An existing active
     * (subject, device) grant is returned unchanged (the no-op grant).
     *
     * <h3>own-domain wall (parity with remote-install)</h3>
     * The acting admin's {@code scope} is threaded in so a SCOPED admin may grant ONLY on a
     * device resident in their OWN brand — a brandX-scoped admin granting on a brandY device
     * is DENIED (mirrors {@link DesktopRemoteInstallService#remoteInstall}'s cross-domain
     * wall). A SUPERADMIN is unscoped ({@code scope.scoped() == false}) and may grant on any
     * non-superadmin device. {@code revoke}/{@code list} were already domain-scoped; this
     * closes the asymmetric grant gap.
     *
     * <h3>active device-ssh-license precondition (parity with remote-install)</h3>
     * After the own-domain wall and the SUPERADMIN-owned rejection, the acting admin
     * ({@code grantedBy}, the ssh-license operator key) must ALSO hold an ACTIVE
     * device-ssh-license covering the resolved device — a DEVICE license on THIS device, OR
     * a DOMAIN license on the device's residency — exactly as
     * {@link DesktopRemoteInstallService#remoteInstall} requires via
     * {@code holdsActiveLicense}. No active license → denied (surfaced as
     * {@link DesktopRemoteInstallService.RemoteInstallDeniedException}, mapped to 403 by the
     * controller, the SAME status family as the remote-install license denial). This check is
     * role-agnostic: remote-install runs {@code holdsActiveLicense} for EVERY role (only the
     * cross-domain wall is superadmin-exempt via {@code scope.scoped()}), so a SUPERADMIN is
     * NOT exempt from the license here either — mirrored for consistency.
     */
    public Mono<DesktopSudoGrant> grant(String subject, String deviceId, String grantedBy, PrincipalDomain scope) {
        return devices.findById(deviceId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException(
                        "device " + deviceId + " is not registered")))
                // Apply domain-wall + superadmin-node guard + license check then write the grant.
                .flatMap(device -> checkDeviceAndGrant(device, subject, deviceId, grantedBy, scope));
    }

    /** Apply own-domain wall + superadmin-node guard + license check then write the grant row. */
    private Mono<DesktopSudoGrant> checkDeviceAndGrant(Device device, String subject,
                                                        String deviceId, String grantedBy,
                                                        PrincipalDomain scope) {
        // own-domain wall: a scoped admin may only grant on an own-domain device.
        if (scope != null && scope.scoped() && !scope.domain().equals(device.domain())) {
            log.warn("[desktop-sudo] DENY cross-domain grant: subject={} scope-domain={} "
                    + "device-domain={}", subject, scope.domain(), device.domain());
            return Mono.error(new IllegalArgumentException("device is not in your domain"));
        }
        if (device.isSuperadminOwned()) {
            return Mono.error(new IllegalArgumentException(
                    "cannot grant desktop sudo on a SUPERADMIN-owned device"));
        }
        // device-ssh-license precondition: the acting admin must hold an ACTIVE ssh-license.
        return holdsActiveLicense(grantedBy, device)
                .flatMap(ok -> writeGrantIfLicensed(ok, subject, deviceId, device, grantedBy));
    }

    /** Write the sudo grant if the license check passed; deny with 403-mapped exception otherwise. */
    private Mono<DesktopSudoGrant> writeGrantIfLicensed(boolean ok, String subject,
                                                         String deviceId, Device device,
                                                         String grantedBy) {
        if (!ok) {
            log.warn("[desktop-sudo] DENY no active ssh-license: grantedBy={} "
                    + "subject={} device={} domain={}", grantedBy, subject, deviceId, device.domain());
            return Mono.error(
                    new DesktopRemoteInstallService.RemoteInstallDeniedException(
                            "you hold no active SSH license for this device"));
        }
        return repo.findActive(subject, deviceId)
                .doOnNext(existing -> log.info(
                        "[desktop-sudo] grant already active for {} on device {} (id={}) — no-op",
                        subject, deviceId, existing.id()))
                .switchIfEmpty(Mono.defer(() -> repo.maxGeneration().flatMap(maxGen ->
                        repo.insertActive(subject, deviceId, device.domain(), grantedBy, maxGen + 1)
                                .doOnNext(g -> log.info(
                                        "[desktop-sudo] granted sudo {} on device {} domain={} gen={} (id={})",
                                        subject, deviceId, device.domain(), g.generation(), g.id()))
                                // Push the new grant to the IdP (Casdoor desktop-sudo role) inline;
                                // best-effort — the row is already the desired state, the worker retries.
                                .flatMap(this::propagateAndStamp))));
    }

    /**
     * Push one just-mutated row through the claim-sync seam and stamp the outcome on
     * {@code propagation_state} (only when it changed — the fresh row is already
     * {@code pending}, so a dark/dry-run push writes nothing). BEST-EFFORT by contract:
     * {@link DesktopSudoClaimSync#propagate} never errors, and even a failed STAMP write is
     * swallowed (logged) — the mutate has already succeeded and the
     * {@link DesktopSudoClaimReconciler} sweep re-drives anything not {@code applied}.
     */
    private Mono<DesktopSudoGrant> propagateAndStamp(DesktopSudoGrant g) {
        return claimSync.propagate(g)
                .flatMap(state -> state.equals(g.propagationState())
                        ? Mono.just(g)
                        : repo.updatePropagationState(g.id(), state)
                                .thenReturn(g.withPropagationState(state)))
                .onErrorResume(e -> {
                    log.warn("[desktop-sudo] claim propagation stamp for id={} failed "
                            + "(worker retries): {}", g.id(), e.toString());
                    return Mono.just(g);
                });
    }

    /** True iff {@code operator} holds an ACTIVE ssh-license covering {@code device} — a
     *  DEVICE license on the device id, OR a DOMAIN license on the device's residency. The
     *  SAME matching semantics as {@link DesktopRemoteInstallService}. */
    private Mono<Boolean> holdsActiveLicense(String operator, Device device) {
        Mono<SshLicense> deviceLic = licenses.findActiveDevice(operator, device.id());
        Mono<SshLicense> domainLic = licenses.findActiveDomain(operator, device.domain());
        return deviceLic.map(l -> true)
                .switchIfEmpty(domainLic.map(l -> true))
                .defaultIfEmpty(false);
    }

    /** Revoke a grant by id (CAS {@code active -> revoked}, NEVER deleted = audit) at the
     *  next monotonic generation; marks propagation pending, then pushes the removal to the
     *  IdP inline (Casdoor role drop when no other active grant remains, best-effort — the
     *  worker retries; see the class javadoc for the honest next-refresh session semantics).
     *  Returns rows-updated (1 = revoked, 0 = already revoked / absent / out of scope). */
    public Mono<Long> revoke(String grantId, String revokedBy, PrincipalDomain scope) {
        return repo.maxGeneration().flatMap(maxGen ->
                repo.revoke(grantId, revokedBy, maxGen + 1, scope)
                        .doOnNext(n -> log.info("[desktop-sudo] revoke id={} by={} gen={} rows={}",
                                grantId, revokedBy, maxGen + 1, n))
                        .flatMap(n -> n == 0
                                ? Mono.just(n)
                                // Only the CAS WINNER pushes (n==1): re-read the now-revoked row
                                // so the sync sees the post-CAS state, then stamp the outcome.
                                : repo.findById(grantId)
                                        .flatMap(this::propagateAndStamp)
                                        .then(Mono.just(n))));
    }

    /** ALL grants VISIBLE to the given tenant scope — the ADMIN read surface. */
    public Flux<DesktopSudoGrant> list(PrincipalDomain scope) {
        return repo.list(scope);
    }

    /**
     * The sudo ENTITLEMENT for (subject, deviceId) — what the IdP/desktop reads to decide
     * whether to mint the {@code desktop-sudo} claim. Returns the active grant, or empty
     * (NO sudo — default-none or revoked). UNSCOPED: the IdP is a trusted internal caller
     * keyed by the subject+device, not a brand-scoped admin.
     */
    public Mono<DesktopSudoGrant> entitlement(String subject, String deviceId) {
        return repo.activeForSubjectAndDevice(subject, deviceId);
    }

    /** The active sudo grants on one device (the per-device entitlement view). */
    public Flux<DesktopSudoGrant> entitlementsForDevice(String deviceId) {
        return repo.activeForDevice(deviceId);
    }
}
