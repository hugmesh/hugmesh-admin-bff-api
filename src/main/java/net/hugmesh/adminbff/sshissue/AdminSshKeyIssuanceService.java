package net.hugmesh.adminbff.sshissue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.SshLicense;
import net.hugmesh.adminbff.device.SshLicenseRepository;
import net.hugmesh.adminbff.device.SshLicenseService;
import net.hugmesh.adminbff.lease.LeaderElection;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Admin SSH key-ISSUANCE application service (SSH PR-4, Option B). MINTS an Ed25519 keypair for
 * an operator to SSH into a licensed device, registers its SHA256 fingerprint into the backing
 * {@code device_ssh_license} (the enforcement record the node pins via its
 * {@code AuthorizedKeysCommand}), records a NON-SECRET issuance AUDIT row, and HOLDS the private
 * key in a short-TTL, leader-pinned, single-use in-memory store for ONE download.
 *
 * <h3>SHIPS DARK</h3>
 * {@code app.ssh-issue.enabled=false} by default. While dark, EVERY mutating verb refuses early
 * with a {@link SshIssueDarkException} (mapped to 503 by the controller) BEFORE any keygen / DB
 * write / license mutation — but the AUTHORIZATION (role + own-domain + superadmin-owned + active
 * read scope) is REAL and tested even while dark.
 *
 * <h3>Authorization (clone of {@link
 * net.hugmesh.adminbff.desktop.DesktopRemoteInstallService#authorizeTerminal})</h3>
 * The target device must be registered, in the acting principal's OWN domain (a SUPERADMIN is
 * unscoped), and NOT SUPERADMIN-owned (superadmin reach is mesh-membership, never a license).
 *
 * <h3>Private-key custody (clone of {@link
 * net.hugmesh.adminbff.workload.WorkloadStepUpService})</h3>
 * The minted private key lives ONLY in {@link #held} — a {@link ConcurrentHashMap} keyed by
 * (subject, issuedKeyId), pinned to the {@link LeaderElection} leader (a non-leader cannot hold/
 * deliver, and a leader flip drops outstanding keys), with a short TTL and a single-use
 * {@link #consume}. It is NEVER persisted, NEVER logged, NEVER returned from {@link #issue}, and
 * dropped after the one download (or TTL expiry).
 */
@Service
public class AdminSshKeyIssuanceService {

    private static final Logger log = LoggerFactory.getLogger(AdminSshKeyIssuanceService.class);

    /** Short TTL — a minted private key is downloadable only briefly after issue. */
    public static final Duration HELD_KEY_TTL = Duration.ofMinutes(5);

    private final boolean enabled;
    private final DeviceRegistryRepository devices;
    private final SshLicenseRepository licenses;
    private final SshLicenseService licenseService;
    private final AdminSshIssuedKeyRepository issued;
    private final LeaderElection leader;

    /** (subject, issuedKeyId) -> held private key + expiry. In-memory + leader-pinned: a leader
     *  flip recreates the service (new map) so outstanding keys do not survive. */
    private final Map<HeldKeyId, HeldKey> held = new ConcurrentHashMap<>();

    public AdminSshKeyIssuanceService(
            @Value("${app.ssh-issue.enabled:false}") boolean enabled,
            DeviceRegistryRepository devices,
            SshLicenseRepository licenses,
            SshLicenseService licenseService,
            AdminSshIssuedKeyRepository issued,
            LeaderElection leader) {
        this.enabled = enabled;
        this.devices = devices;
        this.licenses = licenses;
        this.licenseService = licenseService;
        this.issued = issued;
        this.leader = leader;
    }

    public boolean isEnabled() {
        return enabled;
    }

    private record HeldKeyId(String subject, String issuedKeyId) {
    }

    private record HeldKey(Ed25519KeyMaterial material, Instant expiresAt) {
    }

    // ── issue ───────────────────────────────────────────────────────────────────────

    /**
     * Issue an Ed25519 SSH credential for {@code actor} to reach {@code deviceId}. Fail-closed:
     * dark -> 503 (no keygen); unregistered / cross-domain / superadmin-owned device -> 403.
     *
     * <p>On success: mints the keypair, ADDS its fingerprint to a DEVICE-scoped license for
     * (actor, device) — extending an existing active row via {@code replaceFingerprints} or
     * granting a fresh row — ROTATION-REPLACES any prior {@code issued} credential for the SAME
     * (actor, device) (revoking the audit row + dropping its fingerprint from the license so the
     * active set stays bounded), inserts the NON-SECRET audit row, and HOLDS the private key for
     * ONE leader-pinned download. Returns a result WITHOUT the private key.
     */
    public Mono<IssueResult> issue(String actor, String deviceId, PrincipalDomain scope) {
        if (!enabled) {
            return Mono.error(new SshIssueDarkException());
        }
        if (!leader.isLeader()) {
            // The held-key store is leader-pinned; a non-leader replica must not mint (it could
            // not deliver the download). Fail closed.
            return Mono.error(new SshIssueDeniedException(
                    "issue can only be served by the Lease leader (" + leader.label() + ")"));
        }
        return authorizeDevice(actor, deviceId, scope)
                // Generate key material, register fp, rotate prior, insert audit, hold private key.
                .flatMap(device -> issueForDevice(actor, device));
    }

    /** Register {@code fingerprint} into a DEVICE license for (actor, device): extend the active
     *  row's fingerprint set (bump generation) if one exists, else grant a fresh device license. */
    private Mono<SshLicense> registerFingerprint(String actor, Device device, String fingerprint) {
        return licenses.findActiveDevice(actor, device.id())
                // Add fp to existing license, or grant a new device license if none exists.
                .flatMap(existing -> addFingerprintToLicense(existing, actor, fingerprint))
                .switchIfEmpty(Mono.defer(() ->
                        licenseService.grantDevice(actor, device.id(), List.of(fingerprint), actor)));
    }

    /** Revoke any PRIOR {@code issued} credential for (actor, device) and drop its fingerprint
     *  from the backing license — so the active set stays bounded (rotation-replaces). The
     *  just-added fingerprint {@code keepFp} is never dropped. */
    @SuppressWarnings("PMD.UnusedFormalParameter")
    private Mono<Void> rotateReplacePrior(String actor, Device device, String keepFp, SshLicense license) {
        return issued.findActiveForOperatorDevice(actor, device.id())
                .flatMap(prior -> revokeIssuedRow(prior, actor, PrincipalDomain.superadminFor(device.domain()), keepFp))
                .then();
    }

    /** Generate key material, register its fingerprint, rotate prior, insert audit, and hold the private key. */
    private Mono<IssueResult> issueForDevice(String actor, Device device) {
        Ed25519KeyMaterial material = Ed25519KeyMaterial.generate();
        String fp = material.fingerprint();
        return registerFingerprint(actor, device, fp)
                .flatMap(license -> buildIssueResult(actor, device, fp, license, material));
    }

    /** Rotate prior creds, insert the audit row, hold the private key, and build the result. */
    private Mono<IssueResult> buildIssueResult(String actor, Device device, String fp,
                                                SshLicense license, Ed25519KeyMaterial material) {
        return rotateReplacePrior(actor, device, fp, license)
                .then(insertAudit(actor, device, license, material, fp))
                .map(row -> {
                    hold(actor, row.id(), material);
                    log.info("[ssh-issue] ISSUED credential id={} operator={} device={} "
                                    + "domain={} fp={} license={} (private key held, ttl={}m)",
                            row.id(), actor, device.id(), device.domain(), fp,
                            license.id(), HELD_KEY_TTL.toMinutes());
                    return new IssueResult(row.id(), fp, material.publicOpenSshLine(),
                            device.lastSeenAt(), staleWarning(device.lastSeenAt()));
                });
    }

    /** Add a fingerprint to an existing license (bump generation), or return it unchanged if already pinned. */
    private Mono<SshLicense> addFingerprintToLicense(SshLicense existing, String actor, String fingerprint) {
        Set<String> fps = new LinkedHashSet<>(existing.fingerprints());
        if (fps.contains(fingerprint)) {
            return Mono.just(existing); // already pinned (shouldn't happen — fresh fp)
        }
        fps.add(fingerprint);
        String joined = SshLicenseService.joinFingerprints(new ArrayList<>(fps));
        return licenses.maxGeneration().flatMap(maxGen ->
                licenses.replaceFingerprints(existing.id(), joined, maxGen + 1).thenReturn(existing));
    }

    private Mono<AdminSshIssuedKey> insertAudit(String actor, Device device, SshLicense license,
                                                Ed25519KeyMaterial material, String fingerprint) {
        AdminSshIssuedKey draft = new AdminSshIssuedKey(
                null, device.id(), license.id(), actor, material.keyType(),
                material.publicOpenSshLine(), fingerprint, actor, null, null,
                AdminSshIssuedKey.STATE_ISSUED, device.domain(), null, null);
        return issued.insert(draft);
    }

    private void hold(String subject, String issuedKeyId, Ed25519KeyMaterial material) {
        held.put(new HeldKeyId(subject, issuedKeyId),
                new HeldKey(material, Instant.now().plus(HELD_KEY_TTL)));
    }

    // ── download (single-use) ────────────────────────────────────────────────────────

    /**
     * Consume + return the held private key bytes ONCE for {@code actor}'s {@code issuedKeyId}.
     * Absent / expired / wrong-subject / non-leader -> {@link SshIssueGoneException} (410 Gone).
     * Stamps {@code downloaded_at} (best-effort durable audit). The caller streams the bytes and
     * MUST wipe them in {@code doFinally}; this method also wipes the held material after copy.
     */
    public Mono<byte[]> downloadPrivateKey(String actor, String issuedKeyId) {
        if (!enabled) {
            return Mono.error(new SshIssueDarkException());
        }
        if (!leader.isLeader()) {
            // Only the leader holds the key; a non-leader can never deliver it.
            return Mono.error(new SshIssueGoneException(
                    "no downloadable key on this replica (not the Lease leader)"));
        }
        HeldKey entry = consume(actor, issuedKeyId);
        if (entry == null) {
            return Mono.error(new SshIssueGoneException(
                    "the one-time private key is no longer available (already downloaded or expired)"));
        }
        byte[] bytes = entry.material().privateKeyBytes();
        entry.material().wipe();
        return issued.markDownloaded(issuedKeyId)
                .doOnNext(n -> log.info("[ssh-issue] DOWNLOADED one-time private key id={} (audit-stamped rows={})",
                        issuedKeyId, n))
                .thenReturn(bytes);
    }

    /** Single-use consume: remove + return the held key iff present, not expired, and for this
     *  (subject, id). Expired entries are evicted and treated as absent. */
    private HeldKey consume(String subject, String issuedKeyId) {
        HeldKeyId key = new HeldKeyId(subject, issuedKeyId);
        HeldKey entry = held.remove(key);
        if (entry == null) {
            return null;
        }
        if (Instant.now().isAfter(entry.expiresAt())) {
            entry.material().wipe();
            return null;
        }
        return entry;
    }

    // ── revoke ─────────────────────────────────────────────────────────────────────

    /**
     * Revoke an issued credential: CAS {@code issued -> revoked} (audited, never deleted) AND
     * remove its fingerprint from the backing license (bumping generation so the export drives
     * the removal forward); if it was the license's ONLY fingerprint, revoke the whole license
     * row via {@link SshLicenseService#revoke}. Returns rows-updated (1 = revoked, 0 = already
     * revoked / absent / out of scope).
     */
    public Mono<Long> revoke(String actor, String issuedKeyId, PrincipalDomain scope) {
        if (!enabled) {
            return Mono.error(new SshIssueDarkException());
        }
        return issued.findById(issuedKeyId)
                .flatMap(row -> {
                    // own-domain wall for a scoped principal (defence-in-depth; controller is
                    // SUPERADMIN-only). A cross-brand row is invisible -> reported as 0 rows.
                    if (scope != null && scope.scoped() && !scope.domain().equals(row.domain())) {
                        return Mono.just(0L);
                    }
                    return revokeIssuedRow(row, actor, scope, null);
                })
                .defaultIfEmpty(0L);
    }

    /**
     * The shared revoke body: CAS the audit row, then drop its fingerprint from the backing
     * license. {@code keepFp} (when non-null) is the fingerprint that must remain (the
     * just-issued one during a rotation) — it is never removed even if equal. Drops the held
     * private key too (a revoked credential is never downloadable).
     */
    private Mono<Long> revokeIssuedRow(AdminSshIssuedKey row, String actor, PrincipalDomain scope, String keepFp) {
        return issued.revoke(row.id(), actor, scope)
                // Drop the held key and unpin the fingerprint from the license only if we won the CAS.
                .flatMap(n -> dropHeldKeyAndUnpin(n, row, keepFp));
    }

    /** Remove {@code row.fingerprint()} from its backing license (bump generation); if it was the
     *  ONLY fingerprint, revoke the whole license row. {@code keepFp} is never removed. */
    private Mono<Void> dropFingerprintFromLicense(AdminSshIssuedKey row, String keepFp) {
        if (row.fingerprint() == null || row.fingerprint().equals(keepFp)) {
            return Mono.empty();
        }
        return licenses.findById(row.licenseId())
                // Remove the fingerprint from the license, or revoke the license if it was the last pin.
                .flatMap(license -> removeFingerprintOrRevokeLicense(license, row));
    }

    /** Release held key and unpin the fingerprint from its license only when the CAS won (n > 0). */
    private Mono<Long> dropHeldKeyAndUnpin(Long n, AdminSshIssuedKey row, String keepFp) {
        if (n == 0L) {
            return Mono.just(0L); // lost the CAS / out of scope — nothing to unpin
        }
        HeldKey dropped = held.remove(new HeldKeyId(row.operator(), row.id()));
        if (dropped != null) {
            dropped.material().wipe();
        }
        return dropFingerprintFromLicense(row, keepFp).thenReturn(n);
    }

    /** Remove this row's fingerprint from the license, or revoke the whole license if it was the last pin. */
    private Mono<Void> removeFingerprintOrRevokeLicense(SshLicense license, AdminSshIssuedKey row) {
        if (!license.isActive()) {
            return Mono.empty(); // already revoked — nothing to do
        }
        Set<String> remaining = new LinkedHashSet<>(license.fingerprints());
        remaining.remove(row.fingerprint());
        if (remaining.isEmpty()) {
            // The credential was the license's last pin → revoke the whole license.
            return licenseService.revoke(license.id(), license.grantedBy(),
                    PrincipalDomain.superadminFor(license.domain())).then();
        }
        String joined = SshLicenseService.joinFingerprints(new ArrayList<>(remaining));
        return licenses.maxGeneration()
                .flatMap(maxGen -> licenses.replaceFingerprints(license.id(), joined, maxGen + 1))
                .then();
    }

    // ── list ───────────────────────────────────────────────────────────────────────

    /** Active issued credentials targeting one device, scoped to the principal's brand (ADMIN
     *  own-domain; SUPERADMIN all). Read is allowed even while dark (authorization is real). */
    public Flux<AdminSshIssuedKey> listForDevice(String deviceId, PrincipalDomain scope) {
        return issued.findActiveForDevice(deviceId, scope);
    }

    // ── shared authorize (clone of DesktopRemoteInstallService.authorizeTerminal) ──────

    /** Resolve + authorize the target device: registered, own-domain (superadmin unscoped), NOT
     *  superadmin-owned. Errors with {@link SshIssueDeniedException} (403) on any failure. */
    private Mono<Device> authorizeDevice(String actor, String deviceId, PrincipalDomain scope) {
        return devices.findById(deviceId)
                .switchIfEmpty(Mono.error(new SshIssueDeniedException(
                        "device " + deviceId + " is not registered")))
                // Guard cross-domain and superadmin-owned nodes before authorizing.
                .flatMap(device -> guardDeviceAuthorization(device, actor, deviceId, scope));
    }

    /** Deny cross-domain or superadmin-owned device; allow otherwise. */
    private Mono<Device> guardDeviceAuthorization(Device device, String actor, String deviceId,
                                                   PrincipalDomain scope) {
        if (scope != null && scope.scoped() && !scope.domain().equals(device.domain())) {
            log.warn("[ssh-issue] DENY cross-domain: operator={} scope-domain={} device-domain={}",
                    actor, scope.domain(), device.domain());
            return Mono.error(new SshIssueDeniedException("device is not in your domain"));
        }
        if (device.isSuperadminOwned()) {
            log.warn("[ssh-issue] DENY superadmin-owned node: operator={} device={}", actor, deviceId);
            return Mono.error(new SshIssueDeniedException(
                    "cannot issue an SSH credential for a SUPERADMIN-owned node — "
                    + "superadmin reach is mesh-membership, not a license"));
        }
        return Mono.just(device);
    }

    /** Warn the UI when the target node has not phoned home recently (the credential will not be
     *  enforceable until it pulls the export). Advisory only. */
    private static boolean staleWarning(Instant lastSeenAt) {
        return lastSeenAt == null || Instant.now().isAfter(lastSeenAt.plus(Duration.ofMinutes(10)));
    }

    /** The issue result — NEVER carries the private key. */
    public record IssueResult(String issuedKeyId, String fingerprint, String publicKey,
                              Instant deviceLastSeenAt, boolean deviceStale) {
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("issuedKeyId", issuedKeyId);
            m.put("fingerprint", fingerprint);
            m.put("publicKey", publicKey);
            m.put("deviceLastSeenAt", deviceLastSeenAt);
            m.put("deviceStale", deviceStale);
            return m;
        }
    }

    /** SHIPS DARK refusal (mapped to 503 by the controller). */
    public static class SshIssueDarkException extends RuntimeException {
        public SshIssueDarkException() {
            super("admin SSH key-issuance ships dark (app.ssh-issue.enabled=false)");
        }
    }

    /** An authorization refusal (mapped to 403 by the controller). */
    public static class SshIssueDeniedException extends RuntimeException {
        public SshIssueDeniedException(String message) {
            super(message);
        }
    }

    /** A one-time-key-no-longer-available refusal (mapped to 410 Gone by the controller). */
    public static class SshIssueGoneException extends RuntimeException {
        public SshIssueGoneException(String message) {
            super(message);
        }
    }
}
