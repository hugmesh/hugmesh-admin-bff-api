package net.hugmesh.adminbff.phone;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.web.dto.PhoneIngestRequest;

/**
 * Records phone-ingest/v1|v2 onboarding records into {@code phone_device} (UPSERT by
 * device_id) and serves the SUPERADMIN fleet reads. The write half is a thin normalizing
 * pass-through to {@link PhoneDeviceRepository} — there is intentionally NO authorization
 * logic here, because the ingest channel confers NO access (mesh access is governed by
 * headscale + the MDM/DPC policy; this is fleet inventory only), mirroring
 * {@link net.hugmesh.adminbff.device.DeviceEnrollmentService}.
 *
 * <p><b>Normalization:</b> the wizard's jq emitter writes {@code ""} (never omits the key)
 * for absent optional facts — e.g. {@code tailscale_ip} on a no-USB operator-attested
 * onboarding, or {@code enrolled_at} before a join completed. Blank strings are trimmed to
 * {@code null} here so the registry rows carry real NULLs, not empty-string look-alikes.
 * The nested objects flatten null-tolerantly: an absent {@code enterprise_profile} or (v2)
 * {@code mdm} object, and a null {@code present}/{@code enrolled} flag inside one, all fold
 * to {@code false} — so a v1 record lands with {@code mdm_enrolled=false} + null mdm facts.
 * The device-reported {@code mdm_provider} (changeset 307) folds a null/blank value (a v1 body
 * has none) to the sovereign {@code 'headwind'} default; {@code intune_device_id} trims to null.
 */
@Service
public class PhoneDeviceService {

    private final PhoneDeviceRepository repo;

    public PhoneDeviceService(PhoneDeviceRepository repo) {
        this.repo = repo;
    }

    /** UPSERT an ingest record; returns the resulting registry row (with the bumped count). */
    public Mono<PhoneDevice> ingest(PhoneIngestRequest b) {
        PhoneIngestRequest.EnterpriseProfile p = b.enterpriseProfile();
        PhoneIngestRequest.Mdm m = b.mdm();
        PhoneIngest r = new PhoneIngest(
                b.deviceId().trim(),
                b.deviceClass().trim(),
                blankToNull(b.serial()),
                blankToNull(b.codename()),
                blankToNull(b.marketingName()),
                blankToNull(b.os()),
                blankToNull(b.osVersion()),
                blankToNull(b.superdomain()),
                blankToNull(b.loginServer()),
                blankToNull(b.tailscaleIp()),
                blankToNull(b.tailscaleHostname()),
                blankToNull(b.role()),
                blankToNull(b.attachedDomain()),
                p != null && Boolean.TRUE.equals(p.present()),
                p == null ? null : p.userId(),
                p == null ? null : blankToNull(p.credentialCustody()),
                m != null && Boolean.TRUE.equals(m.enrolled()),
                m == null ? null : blankToNull(m.dpcPackage()),
                m == null ? null : blankToNull(m.headwindUrl()),
                m == null ? null : blankToNull(m.setVia()),
                m == null ? null : m.enrolledAt(),
                blankToNull(b.attestationUrl()),
                blankToNull(b.auditorPackage()),
                blankToNull(b.attestationVerdict()),
                b.enrolledAt(),
                b.generatedAt(),
                // Device-reported provider (changeset 307): a null/blank provider (a v1 body
                // has no field at all) folds to the sovereign 'headwind' default, so the
                // NOT-NULL column always gets a value; intuneDeviceId trims blank to null.
                providerOrDefault(b.mdmProvider()),
                blankToNull(b.intuneDeviceId()));
        return repo.upsert(r);
    }

    /** The whole phone fleet, newest ingest activity first (the superadmin console read). */
    public Flux<PhoneDevice> list() {
        return repo.listAll();
    }

    /** One registry record by its onboarding-stable device id, empty when unknown. */
    public Mono<PhoneDevice> find(String deviceId) {
        return repo.findByDeviceId(deviceId);
    }

    /** The caller's OWN fleet within their domain (changeset 305) — the FLEET_ADMIN read.
     *  BOTH owner AND domain predicate; a device owned by another subject or in another
     *  domain is never returned. */
    public Flux<PhoneDevice> listOwned(String owner, String domain) {
        return repo.listOwned(owner, domain);
    }

    /** One of the caller's OWN devices by id, scoped to owner AND domain; empty when unknown
     *  OR not owned-by-caller-in-domain (the fleet-admin 404 — no enumeration). */
    public Mono<PhoneDevice> findOwned(String deviceId, String owner, String domain) {
        return repo.findByDeviceIdOwned(deviceId, owner, domain);
    }

    /** A blank/null MDM provider folds to the sovereign 'headwind' default (never null). */
    private static String providerOrDefault(@Nullable String s) {
        String t = blankToNull(s);
        return t == null ? PhoneDevice.MDM_PROVIDER_HEADWIND : t;
    }

    private static @Nullable String blankToNull(@Nullable String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}
