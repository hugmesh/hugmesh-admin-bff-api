package systems.hugmesh.adminbff.phone;

import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * A NORMALIZED phone-ingest/v1|v2 record ready to persist — the service's translation of
 * the wire DTO ({@code PhoneIngestRequest}): optional strings are blank-trimmed to
 * {@code null} (the wizard emits {@code ""} for absent facts, e.g. {@code tailscale_ip} on
 * a no-USB operator-attested onboarding), the nested {@code enterprise_profile} and (v2)
 * {@code mdm} objects are flattened, and the {@code schema} discriminator is dropped
 * (validated upstream, not stored — a v1 record simply flattens to
 * {@code mdmEnrolled=false} + null mdm facts).
 */
public record PhoneIngest(
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
        // Device-reported MDM provider (changeset 307). The service defaults a null/blank
        // provider to 'headwind' (never null here), so the NOT-NULL column always gets a value;
        // intuneDeviceId is null for a Headwind device.
        String mdmProvider,
        @Nullable String intuneDeviceId) {
}
