package systems.hugmesh.adminbff.desktop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.device.Device;
import systems.hugmesh.adminbff.device.DeviceRegistryRepository;
import systems.hugmesh.adminbff.device.SshLicense;
import systems.hugmesh.adminbff.device.SshLicenseRepository;
import systems.hugmesh.commons.security.PrincipalDomain;

/**
 * The REMOTE-INSTALL authorization + trigger — the load-bearing security boundary that
 * RIDES the device-ssh-license (RESOLVED design decision: no new daemon, reuse the
 * device-registry fail-closed authz). The admin may trigger a one-click install ONLY when:
 *
 * <ol>
 *   <li>the target {@code deviceId} is a registered device;</li>
 *   <li>the device's RESIDENCY domain == the acting admin's OWN domain (a SUPERADMIN is
 *       unscoped) — a cross-domain device is DENIED (no reaching another brand's node);</li>
 *   <li>the acting admin (operator == its subject) holds an ACTIVE ssh-license covering the
 *       device — either a DEVICE license on THIS device, OR a DOMAIN license on the device's
 *       residency domain. No active license → DENIED.</li>
 * </ol>
 *
 * Only after all three pass does it run the install over the device-SSH channel — which
 * SHIPS DARK behind {@link DesktopSshClient}'s Noop ({@code app.desktop.remote-install.enabled
 * =false}). The AUTHORIZATION is REAL + tested; the SSH exec is the dark part.
 *
 * <p>Denials are surfaced as {@link RemoteInstallDeniedException} (the controller maps it to
 * 403). The validator is fail-closed: any missing precondition denies.
 */
@Service
public class DesktopRemoteInstallService {

    private static final Logger log = LoggerFactory.getLogger(DesktopRemoteInstallService.class);

    private final DeviceRegistryRepository devices;
    private final SshLicenseRepository licenses;
    private final DesktopAppCatalogRepository catalog;
    private final DesktopSshClient ssh;

    public DesktopRemoteInstallService(DeviceRegistryRepository devices, SshLicenseRepository licenses,
                                       DesktopAppCatalogRepository catalog, DesktopSshClient ssh) {
        this.devices = devices;
        this.licenses = licenses;
        this.catalog = catalog;
        this.ssh = ssh;
    }

    /**
     * Validate the admin's authority + trigger the one-click remote install.
     *
     * @param operator the admin's Casdoor subject (the ssh-license operator key)
     * @param deviceId the target desktop device
     * @param appRef   the app to install (must be in the device-domain's ENABLED allowlist)
     * @param scope    the acting admin's tenant scope (own-domain wall; SUPERADMIN unscoped)
     */
    public Mono<String> remoteInstall(String operator, String deviceId, String appRef, PrincipalDomain scope) {
        return remoteInstall(operator, deviceId, appRef, scope, () -> { });
    }

    /**
     * As {@link #remoteInstall(String, String, String, PrincipalDomain)} but runs {@code onAuthorized}
     * EXACTLY ONCE, immediately AFTER every authorization precondition (registered + own-domain wall
     * + SUPERADMIN-owned-node guard + active ssh-license + ref-in-enabled-allowlist) has passed and
     * BEFORE the (ships-dark) SSH exec — the single-use step-up CONSUME hook so the token is burned
     * only on a real, fully-authorized trigger (never on a denied request, so a denied attempt does
     * not waste the operator's token). A denial never invokes it.
     */
    public Mono<String> remoteInstall(String operator, String deviceId, String appRef, PrincipalDomain scope,
                                      Runnable onAuthorized) {
        return devices.findById(deviceId)
                .switchIfEmpty(Mono.error(new RemoteInstallDeniedException(
                        "device " + deviceId + " is not registered")))
                // Apply tenancy wall + superadmin-node guard + license + catalog checks.
                .flatMap(device -> checkDeviceAndInstall(device, operator, deviceId, appRef, scope, onAuthorized));
    }

    /**
     * Authorize an interactive SSH-TERMINAL session (no app ref): the SAME own-domain wall +
     * SUPERADMIN-owned-node guard + active device-ssh-license check as {@link #remoteInstall},
     * MINUS the catalog-allowlist leg (a terminal installs nothing). Completes empty on
     * success; errors with {@link RemoteInstallDeniedException} (mapped to 403) on any failed
     * precondition. Used by the scaffolded {@link DesktopSshTerminalController}.
     */
    public Mono<Void> authorizeTerminal(String operator, String deviceId, PrincipalDomain scope) {
        return devices.findById(deviceId)
                .switchIfEmpty(Mono.error(new RemoteInstallDeniedException(
                        "device " + deviceId + " is not registered")))
                // Apply tenancy wall + superadmin-node guard + license check for a terminal session.
                .flatMap(device -> checkDeviceForTerminal(device, operator, deviceId, scope))
                .then();
    }

    /** Apply the domain-wall + superadmin-node guard + license + catalog checks then execute the install. */
    private Mono<String> checkDeviceAndInstall(Device device, String operator, String deviceId,
                                               String appRef, PrincipalDomain scope, Runnable onAuthorized) {
        // (2) cross-domain wall: a scoped admin may only reach an own-domain device.
        if (scope != null && scope.scoped() && !scope.domain().equals(device.domain())) {
            log.warn("[desktop-remote-install] DENY cross-domain: operator={} scope-domain={} "
                    + "device-domain={}", operator, scope.domain(), device.domain());
            return Mono.error(new RemoteInstallDeniedException("device is not in your domain"));
        }
        // (2b) SUPERADMIN-owned node guard — superadmin reach is mesh-membership, not a license.
        if (device.isSuperadminOwned()) {
            log.warn("[desktop-remote-install] DENY superadmin-owned node: operator={} device={}",
                    operator, deviceId);
            return Mono.error(new RemoteInstallDeniedException(
                    "cannot remote-install onto a SUPERADMIN-owned node — superadmin "
                    + "reach is mesh-membership, not a license"));
        }
        // (3) active ssh-license precondition: DEVICE license on this device OR DOMAIN license.
        return holdsActiveLicense(operator, device)
                .flatMap(ok -> authorizeAndInstall(ok, operator, deviceId, appRef, device, onAuthorized));
    }

    /** Verify license then look up the catalog entry and execute the install. */
    private Mono<String> authorizeAndInstall(boolean ok, String operator, String deviceId,
                                             String appRef, Device device, Runnable onAuthorized) {
        if (!ok) {
            log.warn("[desktop-remote-install] DENY no active ssh-license: operator={} "
                    + "device={} domain={}", operator, deviceId, device.domain());
            return Mono.error(new RemoteInstallDeniedException(
                    "you hold no active SSH license for this device"));
        }
        // Gate passed — require the ref be in the device-domain's ENABLED allowlist.
        return catalog.findEnabledByRef(device.domain(), appRef)
                .switchIfEmpty(Mono.error(new RemoteInstallDeniedException(
                        "ref is not in this domain's enabled Discover allowlist")))
                .flatMap(entry -> {
                    log.info("[desktop-remote-install] AUTHORIZED operator={} device={} "
                            + "ref={} domain={} ssh-real={}", operator, deviceId, appRef,
                            device.domain(), ssh.isReal());
                    // Burn the single-use step-up token now that authz fully passed.
                    onAuthorized.run();
                    return ssh.remoteInstall(deviceId, device.hostname(), appRef, operator);
                });
    }

    /** Apply the domain-wall + superadmin-node guard + license check for a terminal session. */
    private Mono<Void> checkDeviceForTerminal(Device device, String operator,
                                              String deviceId, PrincipalDomain scope) {
        if (scope != null && scope.scoped() && !scope.domain().equals(device.domain())) {
            return Mono.error(new RemoteInstallDeniedException("device is not in your domain"));
        }
        // SUPERADMIN-owned node guard — same rationale as remoteInstall.
        if (device.isSuperadminOwned()) {
            log.warn("[desktop-ssh-terminal] DENY superadmin-owned node: operator={} device={}",
                    operator, deviceId);
            return Mono.error(new RemoteInstallDeniedException(
                    "cannot open an SSH terminal onto a SUPERADMIN-owned node — superadmin "
                    + "reach is mesh-membership, not a license"));
        }
        return holdsActiveLicense(operator, device).flatMap(ok -> ok
                ? Mono.empty()
                : Mono.error(new RemoteInstallDeniedException(
                        "you hold no active SSH license for this device")));
    }

    /** True iff {@code operator} holds an ACTIVE ssh-license covering {@code device} — a
     *  DEVICE license on the device id, OR a DOMAIN license on the device's residency. */
    private Mono<Boolean> holdsActiveLicense(String operator, Device device) {
        Mono<SshLicense> deviceLic = licenses.findActiveDevice(operator, device.id());
        Mono<SshLicense> domainLic = licenses.findActiveDomain(operator, device.domain());
        return deviceLic.map(l -> true)
                .switchIfEmpty(domainLic.map(l -> true))
                .defaultIfEmpty(false);
    }

    /** Whether the SSH exec channel is REAL (true) or ships dark (false). Surfaced for a
     *  ships-dark structural assertion. */
    public boolean sshIsReal() {
        return ssh.isReal();
    }

    /** A refusal to remote-install (mapped to 403 by the controller). */
    public static class RemoteInstallDeniedException extends RuntimeException {
        public RemoteInstallDeniedException(String message) {
            super(message);
        }
    }
}
