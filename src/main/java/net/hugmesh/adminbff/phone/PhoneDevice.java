package net.hugmesh.adminbff.phone;

import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * One {@code phone_device} row — the MDM PHONE REGISTRY record for an operator-onboarded
 * managed phone (the phone-ingest/v1|v2 shape {@code scripts/phone-wizard.sh} emits and
 * POSTs; the flattened {@code mdm*} Headwind-enrollment facts are the v2 additions —
 * {@code mdmEnrolled=false} + null facts on a v1 record).
 * Keyed on {@code deviceId} (UNIQUE); a re-ingest UPSERTs and bumps {@code ingestCount}.
 *
 * <p><b>NOT an authority.</b> Like {@link net.hugmesh.adminbff.device.DeviceEnrollment}
 * this carries NO authorizing columns — no SSH license, no grant. It is inventory/telemetry a
 * SUPERADMIN reads from the control plane; authorization for anything a phone does on the mesh
 * lives elsewhere (headscale + the MDM/DPC policy), never here.
 *
 * <p><b>Management + lockout (changeset 304) is the ONE exception.</b> The trailing seven
 * components are OPERATOR-AUTHORITATIVE control-plane state, not device telemetry:
 * {@code managementMode} distinguishes an operator-provisioned managed phone
 * ({@code mesh_owned}) from BYOD ({@code unmanaged}) and is written ONLY on the
 * {@code /bff/superadmin/**} plane (SUPERADMIN + step-up) — the {@code mdm*} facts are
 * device-reported HINTS, never the authority — while the {@code lock*} components are the
 * reversible, SUPERADMIN-gated lockout (mirroring {@code device_ssh_license}: a CAS
 * {@code lockState}, a {@code lockGeneration} monotonic across BOTH lock and unlock, and the
 * push-with-ack {@code lockPropagationState}). The ingest path writes NONE of these, so a
 * re-ingest never resets managed/locked status.
 *
 * <p><b>Fleet ownership (changeset 305) is the same trust boundary.</b> The trailing
 * {@code physicalOwner} + {@code ownerDomain} are OPERATOR-AUTHORITATIVE too: set ONLY on the
 * {@code /bff/superadmin/**} plane (SUPERADMIN + step-up), NEVER by the ingest channel, and
 * together they are the SOLE tenancy wall for the public {@code /bff/admin/phone-fleet/**}
 * FLEET_ADMIN surface (every non-superadmin read/mutation is predicated
 * {@code physical_owner = caller AND owner_domain = caller-domain}). Both are read-only fields
 * here — nullable until a superadmin assigns them.
 *
 * <p><b>MDM provider (changeset 307) is DEVICE-REPORTED telemetry, NOT operator state.</b> The
 * trailing {@code mdmProvider} + {@code intuneDeviceId} record which MDM backend the wizard
 * enrolled the device with ('headwind' the sovereign default, or 'azure-intune') — like the 303
 * {@code mdm*} facts they ride the spoofable ingest channel and are ADVISORY. The enforcer fans
 * a lock to the DPC leg matching {@link #effectiveMdmProvider()}, but the control-plane lock
 * state is authoritative regardless: an unknown/spoofed provider only DEGRADES enforcement (no
 * matching leg fires), it can never block or clear the authoritative lock record. A {@code null}
 * provider is treated as {@code 'headwind'} (the default backend).
 */
public record PhoneDevice(
        String id,
        String deviceId,
        String deviceClass,
        @Nullable String serial,
        @Nullable String codename,
        @Nullable String marketingName,
        @Nullable String os,
        @Nullable String osVersion,
        @Nullable String superdomain,
        @Nullable String loginServer,
        @Nullable String tailscaleIp,
        @Nullable String tailscaleHostname,
        @Nullable String role,
        @Nullable String attachedDomain,
        boolean enterpriseProfilePresent,
        @Nullable Long enterpriseProfileUserId,
        @Nullable String enterpriseProfileCredentialCustody,
        boolean mdmEnrolled,
        @Nullable String mdmDpcPackage,
        @Nullable String mdmHeadwindUrl,
        @Nullable String mdmSetVia,
        @Nullable Instant mdmEnrolledAt,
        @Nullable String attestationUrl,
        @Nullable String auditorPackage,
        @Nullable String attestationVerdict,
        @Nullable Instant enrolledAt,
        @Nullable Instant generatedAt,
        Instant firstIngestedAt,
        Instant lastIngestedAt,
        long ingestCount,
        String managementMode,
        String lockState,
        @Nullable String lockPropagationState,
        long lockGeneration,
        @Nullable String lockReason,
        @Nullable String lockActor,
        @Nullable Instant lockUpdatedAt,
        @Nullable String physicalOwner,
        @Nullable String ownerDomain,
        @Nullable String mdmProvider,
        @Nullable String intuneDeviceId) {

    /** Authoritative managed/BYOD discriminator values (changeset 304). */
    public static final String MANAGEMENT_UNMANAGED = "unmanaged";
    public static final String MANAGEMENT_MESH_OWNED = "mesh_owned";

    /** Device-reported MDM-provider values (changeset 307). 'headwind' is the sovereign
     *  self-hosted DEFAULT; a null provider is treated as 'headwind'. */
    public static final String MDM_PROVIDER_HEADWIND = "headwind";
    public static final String MDM_PROVIDER_AZURE_INTUNE = "azure-intune";

    /**
     * The effective MDM provider, folding a null/blank {@code mdmProvider} to the sovereign
     * {@code 'headwind'} default. This is what the enforcer's per-leg {@code appliesTo} matches
     * on — a device that never reported a provider is a Headwind device.
     */
    public String effectiveMdmProvider() {
        return (mdmProvider == null || mdmProvider.isBlank())
                ? MDM_PROVIDER_HEADWIND : mdmProvider;
    }

    /** Reversible lock CAS values (changeset 304). */
    public static final String LOCK_UNLOCKED = "unlocked";
    public static final String LOCK_LOCKED = "locked";

    /** Push-with-ack lock propagation outcomes (mirror device_ssh_license). */
    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";
    public static final String PROP_DEGRADED = "degraded";

    /** True iff this is an operator-provisioned managed phone (the only lockable state). */
    public boolean isManaged() {
        return MANAGEMENT_MESH_OWNED.equals(managementMode);
    }

    /** True iff the device is currently under a control-plane lock. */
    public boolean isLocked() {
        return LOCK_LOCKED.equals(lockState);
    }

    /**
     * A copy with the post-CAS lock state + generation, for the enforcement legs' wire
     * payload. The device read before the atomic bump still carries the OLD generation; the
     * legs stamp {@code generation} into the command a downstream store uses for rollback
     * rejection (incoming &le; last-seen &rArr; drop), so the payload MUST carry the bumped
     * value the authoritative row now holds, not the pre-read one.
     */
    public PhoneDevice withLock(String newLockState, long newLockGeneration) {
        return new PhoneDevice(id, deviceId, deviceClass, serial, codename, marketingName, os,
                osVersion, superdomain, loginServer, tailscaleIp, tailscaleHostname, role,
                attachedDomain, enterpriseProfilePresent, enterpriseProfileUserId,
                enterpriseProfileCredentialCustody, mdmEnrolled, mdmDpcPackage, mdmHeadwindUrl,
                mdmSetVia, mdmEnrolledAt, attestationUrl, auditorPackage, attestationVerdict,
                enrolledAt, generatedAt, firstIngestedAt, lastIngestedAt, ingestCount,
                managementMode, newLockState, lockPropagationState, newLockGeneration, lockReason,
                lockActor, lockUpdatedAt, physicalOwner, ownerDomain, mdmProvider, intuneDeviceId);
    }
}
