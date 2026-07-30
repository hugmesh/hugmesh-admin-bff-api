package systems.hugmesh.adminbff.device;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.util.List;

/**
 * Write/read surface for {@code device_ssh_license} — the explicit
 * (operator x device|domain) SSH grants. SUPERADMIN issues/revokes; ADMIN reads
 * own-domain only. The desired-state pattern mirrors
 * {@link systems.hugmesh.adminbff.domainlock.DomainLockService}: an idempotent grant
 * (findActive-then-insert) + a CAS revoke that NEVER deletes (the row is the audit
 * trail). Every mutate bumps the monotonic {@code generation} so the signed export's
 * rollback guard can reject a replayed payload [FIX-SIGNCACHE / FIX-REVOKE].
 *
 * <h3>FIX-PINKEY</h3>
 * Each grant pins the exact SSH pubkey fingerprint(s) the operator may present
 * ({@code keyFingerprints}); the compiled export only emits a key whose offered
 * {@code %f} matches a pinned fingerprint, so a licensed operator presenting an un-pinned
 * key is still denied.
 */
@Service
public class SshLicenseService {

    private static final Logger log = LoggerFactory.getLogger(SshLicenseService.class);

    private final SshLicenseRepository repo;
    private final DeviceRegistryRepository devices;
    private final DomainRegistry domainRegistry;

    public SshLicenseService(SshLicenseRepository repo, DeviceRegistryRepository devices,
                             DomainRegistry domainRegistry) {
        this.repo = repo;
        this.devices = devices;
        this.domainRegistry = domainRegistry;
    }

    /**
     * Idempotently grant {@code operator} a DEVICE-scoped license on {@code deviceId},
     * pinning {@code keyFingerprints} [FIX-PINKEY]. An existing active (operator,
     * device) license is returned unchanged (the no-op grant); otherwise a new active row
     * is written at the next monotonic generation, stamped with the DEVICE's RESIDENCY
     * domain as the home/tenant discriminator (so the row lands in the brand that owns the
     * node, NOT the granting superadmin's home — keeping the ADMIN read view correct).
     *
     * <h3>POST-VERIFY CORRECTION (2026-06-12) — reject a SUPERADMIN-owned device</h3>
     * A device-license on a SUPERADMIN-owned (core/primary) node is NEVER valid: an ADMIN
     * is denied such a node by hard rule, and SUPERADMIN reaches it via MESH-MEMBERSHIP,
     * not a license row. The unscoped signed export cannot see operator roles, so it must
     * not carry any SUPERADMIN access; the only durable way to keep superadmin-owned nodes
     * OUT of the export is to refuse the grant at the source. We therefore resolve the
     * device FIRST and REJECT a SUPERADMIN-owned target with a 422 (mapped by the
     * controller {@code onErrorResume}). SUPERADMIN mesh-reach is enforced ENTIRELY by the
     * deferred Layer-A headscale policy (per-tenant OIDC user + mesh-membership + a
     * SUPERADMIN rule) — headscale is the mesh-membership source of truth, never the BFF.
     *
     * <h3>(d) residency-stamped domain</h3>
     * {@code license.domain} is stamped from the RESOLVED {@code device.domain()}
     * (residency), never caller-supplied — so a DEVICE license can never claim a different
     * domain than the device it targets.
     */
    public Mono<SshLicense> grantDevice(String operator, String deviceId, List<String> keyFingerprints,
                                        String grantedBy) {
        String fps = joinFingerprints(keyFingerprints);
        // Resolve the device FIRST so the SUPERADMIN-owned guard fires before any write and
        // the license.domain is stamped from the device's residency (d), not the caller.
        return devices.findById(deviceId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException(
                        "device " + deviceId + " is not registered")))
                // Guard superadmin-owned nodes then idempotently insert a DEVICE license.
                .flatMap(device -> grantDeviceLicenseForDevice(device, operator, deviceId, fps, grantedBy));
    }

    /** Guard the superadmin-owned node, then idempotently insert a DEVICE license for this device. */
    private Mono<SshLicense> grantDeviceLicenseForDevice(Device device, String operator,
                                                          String deviceId, String fps,
                                                          String grantedBy) {
        if (device.isSuperadminOwned()) {
            return Mono.error(new IllegalArgumentException(
                    "cannot grant an SSH license on a SUPERADMIN-owned device — "
                    + "superadmin reach is mesh-membership, not a license"));
        }
        return repo.findActiveDevice(operator, deviceId)
                .doOnNext(existing -> log.info(
                        "[ssh-license] DEVICE license already active for {} on device {} (id={}) — no-op",
                        operator, deviceId, existing.id()))
                .switchIfEmpty(Mono.defer(() -> repo.maxGeneration().flatMap(maxGen -> {
                    SshLicense draft = new SshLicense(null, operator, SshLicense.SCOPE_DEVICE,
                            deviceId, null, fps, SshLicense.STATE_ACTIVE, grantedBy, null,
                            null, null, device.domain(), SshLicense.PROP_PENDING, maxGen + 1);
                    return repo.insertActive(draft, maxGen + 1)
                            .doOnNext(l -> log.info(
                                    "[ssh-license] granted DEVICE license {} on device {} domain={} gen={} (id={})",
                                    operator, deviceId, device.domain(), l.generation(), l.id()));
                })));
    }

    /**
     * Idempotently grant {@code operator} a DOMAIN-scoped license on {@code targetDomain}
     * (every node resident in that brand), pinning {@code keyFingerprints} [FIX-PINKEY].
     * The home/tenant discriminator IS the target domain (the grant belongs to that
     * brand). An existing active (operator, domain) license is returned unchanged.
     *
     * <h3>(d) target-domain validation [FIX-NODEFAULT]</h3>
     * {@code targetDomain} MUST be a real, known residency brand — never {@code 'default'}
     * or blank or an unknown domain. A DOMAIN-license on {@code 'default'} would make the
     * clause-2 cross-domain wall vacuous (every node reads as the caller's brand), and a
     * license on an unknown domain matches no node (dead weight). We consult
     * {@link DomainRegistry#isKnownDomain(String)} (the issuer-keyed brand allowlist); the
     * violation is a hard {@link IllegalArgumentException} mapped to a 422 by the
     * controller, never a silently-useless license.
     */
    public Mono<SshLicense> grantDomain(String operator, String targetDomain, List<String> keyFingerprints,
                                        String grantedBy) {
        if (targetDomain == null || targetDomain.isBlank()
                || DomainRegistry.DEFAULT_DOMAIN.equals(targetDomain)) {
            return Mono.error(new IllegalArgumentException(
                    "DOMAIN-license target must be a real residency domain, not 'default'/blank "
                    + "[FIX-NODEFAULT]"));
        }
        if (!domainRegistry.isKnownDomain(targetDomain)) {
            return Mono.error(new IllegalArgumentException(
                    "DOMAIN-license target '" + targetDomain + "' is not a known residency domain "
                    + "(no node resident in it could ever be reached)"));
        }
        String fps = joinFingerprints(keyFingerprints);
        return repo.findActiveDomain(operator, targetDomain)
                .doOnNext(existing -> log.info(
                        "[ssh-license] DOMAIN license already active for {} on domain {} (id={}) — no-op",
                        operator, targetDomain, existing.id()))
                .switchIfEmpty(Mono.defer(() -> repo.maxGeneration().flatMap(maxGen -> {
                    SshLicense draft = new SshLicense(null, operator, SshLicense.SCOPE_DOMAIN,
                            null, targetDomain, fps, SshLicense.STATE_ACTIVE, grantedBy, null,
                            null, null, targetDomain, SshLicense.PROP_PENDING, maxGen + 1);
                    return repo.insertActive(draft, maxGen + 1)
                            .doOnNext(l -> log.info(
                                    "[ssh-license] granted DOMAIN license {} on domain {} gen={} (id={})",
                                    operator, targetDomain, l.generation(), l.id()));
                })));
    }

    /**
     * Revoke a license by id (CAS {@code active -> revoked}, NEVER deleted = audit) at the
     * next monotonic generation, stamping {@code revoked_by} and marking propagation
     * {@code pending} so the push-with-ack to both enforcement layers is reconciled
     * forward [FIX-REVOKE]. Returns the rows-updated count (1 = revoked, 0 = already
     * revoked / absent / out of scope). SUPERADMIN-gated at the controller (unscoped path).
     */
    public Mono<Long> revoke(String licenseId, String revokedBy, PrincipalDomain scope) {
        return repo.maxGeneration().flatMap(maxGen ->
                repo.revoke(licenseId, revokedBy, maxGen + 1, scope)
                        .doOnNext(n -> log.info("[ssh-license] revoke id={} by={} gen={} rows={}",
                                licenseId, revokedBy, maxGen + 1, n)));
    }

    /** ALL licenses VISIBLE to the given tenant scope — the ADMIN read surface
     *  (own-domain only; SUPERADMIN sees all). */
    public Flux<SshLicense> list(PrincipalDomain scope) {
        return repo.list(scope);
    }

    /** Active DEVICE licenses targeting one device id, VISIBLE to the given scope. */
    public Flux<SshLicense> activeForDevice(String deviceId, PrincipalDomain scope) {
        return repo.activeForDevice(deviceId, scope);
    }

    /** FIX-PINKEY: normalise the pinned fingerprints into the stored comma-separated form
     *  (blanks dropped). A null/empty list stores NULL (the license pins no key — the
     *  export emits nothing for it, fail-closed). */
    public static String joinFingerprints(List<String> fingerprints) {
        if (fingerprints == null || fingerprints.isEmpty()) return null;
        StringBuilder sb = new StringBuilder();
        for (String f : fingerprints) {
            if (f == null) continue;
            String t = f.trim();
            if (t.isEmpty()) continue;
            if (sb.length() > 0) sb.append(',');
            sb.append(t);
        }
        return sb.length() == 0 ? null : sb.toString();
    }
}
