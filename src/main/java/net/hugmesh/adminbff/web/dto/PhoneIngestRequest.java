package net.hugmesh.adminbff.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * Body for {@code POST /bff/internal/device-registry/phone-ingest} — the
 * {@code phone-ingest/v1}|{@code v2} record {@code scripts/phone-wizard.sh ingest} emits at
 * the end of MDM phone onboarding (mTLS, NO JWT). v2 is STRICTLY ADDITIVE over v1: every v1
 * field is unchanged and one nested {@code mdm} object (the Headwind enrollment facts)
 * rides along — a v1 record simply binds a null {@code mdm}. It carries ONLY fleet
 * inventory/telemetry; there are NO authorizing fields (no owner, no license, no grant) by
 * design — an ingest record is operator-/device-reported and can never confer access. The
 * trust gates are headscale + the MDM/DPC policy; this just gives a SUPERADMIN a queryable
 * phone registry.
 *
 * <p><b>Wire naming — snake_case (unlike the sibling ingest DTOs).</b> The wizard emits jq
 * snake_case keys ({@code device_id}, {@code os_version}, {@code tailscale_ip} …), so EVERY
 * multi-word component carries {@code @JsonProperty} (the {@code AnnouncementRequest}
 * pattern) — a camelCase record shaped like {@code SelfReportRequest} would silently bind
 * nulls. Unknown keys are ignored explicitly ({@code @JsonIgnoreProperties}) so a future
 * additive wizard field never breaks ingest (the external-producer convention:
 * {@code ImageBuildProgressRequest}).
 *
 * <p><b>Blank-vs-absent.</b> The jq emitter writes {@code ""} rather than omitting absent
 * facts (e.g. {@code tailscale_ip} on a no-USB operator-attested onboarding), so optional
 * strings validate {@code @Size} only and the service trims blank to {@code null} before
 * persisting. The two operator timestamps are ISO-8601 strings mapped to {@link Instant};
 * an empty string binds to {@code null} (Jackson java-time leniency, covered by test).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record PhoneIngestRequest(

        /* The contract discriminator — EXACTLY the two additive revisions this DTO can
         * represent; anything else (a v3, a node record family) is a clean 400 (the node
         * self-report contract is the mirror image: it rejects phone records). */
        @NotBlank(message = "schema is required")
        @Pattern(regexp = "phone-ingest/v1|phone-ingest/v2",
                 message = "schema must be phone-ingest/v1 or phone-ingest/v2")
        String schema,

        @JsonProperty("device_id")
        @NotBlank(message = "device_id is required")
        @Size(max = 128, message = "device_id is too long")
        String deviceId,

        @JsonProperty("device_class")
        @NotBlank(message = "device_class is required")
        @Pattern(regexp = "phone", message = "device_class must be phone")
        String deviceClass,

        @Size(max = 128, message = "serial is too long")
        @Nullable
        String serial,

        @Size(max = 64, message = "codename is too long")
        @Nullable
        String codename,

        @JsonProperty("marketing_name")
        @Size(max = 128, message = "marketing_name is too long")
        @Nullable
        String marketingName,

        @Size(max = 64, message = "os is too long")
        @Nullable
        String os,

        @JsonProperty("os_version")
        @Size(max = 64, message = "os_version is too long")
        @Nullable
        String osVersion,

        @Size(max = 253, message = "superdomain is too long")
        @Nullable
        String superdomain,

        @JsonProperty("login_server")
        @Size(max = 512, message = "login_server is too long")
        @Nullable
        String loginServer,

        @JsonProperty("tailscale_ip")
        @Size(max = 64, message = "tailscale_ip is too long")
        @Nullable
        String tailscaleIp,

        @JsonProperty("tailscale_hostname")
        @Size(max = 253, message = "tailscale_hostname is too long")
        @Nullable
        String tailscaleHostname,

        @Size(max = 64, message = "role is too long")
        @Nullable
        String role,

        @JsonProperty("attached_domain")
        @Size(max = 253, message = "attached_domain is too long")
        @Nullable
        String attachedDomain,

        /* @Valid is REQUIRED on the parent field for validation to cascade into the
         * nested record (the BatchTriggerImageBuildRequest.entries precedent). */
        @JsonProperty("enterprise_profile")
        @Valid
        @Nullable
        EnterpriseProfile enterpriseProfile,

        /* The phone-ingest/v2 additive object — null on every v1 record. @Valid cascades
         * (the enterprise_profile precedent above). */
        @JsonProperty("mdm")
        @Valid
        @Nullable
        Mdm mdm,

        @JsonProperty("attestation_url")
        @Size(max = 512, message = "attestation_url is too long")
        @Nullable
        String attestationUrl,

        @JsonProperty("auditor_package")
        @Size(max = 253, message = "auditor_package is too long")
        @Nullable
        String auditorPackage,

        @JsonProperty("attestation_verdict")
        @Size(max = 64, message = "attestation_verdict is too long")
        @Nullable
        String attestationVerdict,

        @JsonProperty("enrolled_at")
        @Nullable
        Instant enrolledAt,

        @JsonProperty("generated_at")
        @Nullable
        Instant generatedAt,

        /* phone-ingest/v2 ADDITIVE top-level MDM-provider telemetry (changeset 307): which
         * backend the wizard enrolled with — 'headwind' (sovereign default) or 'azure-intune'.
         * Nullable/blank on a v1 body (no provider field) → the service defaults it to
         * 'headwind'. @Pattern pins the two co-equal values (a spoofed value is a clean 400).
         * A wizard that emits "" (the jq blank-not-omit convention) passes @Pattern via the
         * regex alternation with an empty option and folds to 'headwind' in the service. */
        @JsonProperty("mdm_provider")
        @Pattern(regexp = "headwind|azure-intune|",
                 message = "mdm_provider must be headwind or azure-intune")
        @Nullable
        String mdmProvider,

        /* The Graph managedDevice id the Intune remoteLock leg targets; null/blank for a
         * Headwind device (the service trims blank to null). Sized like the device id band. */
        @JsonProperty("intune_device_id")
        @Size(max = 128, message = "intune_device_id is too long")
        @Nullable
        String intuneDeviceId) {

    /**
     * The separately-encrypted on-device enterprise (work) profile facts, if provisioned:
     * {@code present}, the AOSP secondary-user id ({@code user_id}, null when absent), and
     * where the profile passphrase is escrowed ({@code credential_custody}, "vault-seed").
     * {@code present} is a BOXED Boolean deliberately: Jackson 3's record binding 400s an
     * omitted primitive component (the legacy FAIL_ON_NULL_FOR_PRIMITIVES leniency does
     * not reach it — proven by test), and a future producer omitting the flag must not
     * break ingest. Absent/null folds to {@code false} in the service.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record EnterpriseProfile(
            @Nullable
            Boolean present,

            @JsonProperty("user_id")
            @Nullable
            Long userId,

            @JsonProperty("credential_custody")
            @Size(max = 64, message = "credential_custody is too long")
            @Nullable
            String credentialCustody) {
    }

    /**
     * The phone-ingest/v2 Headwind MDM enrollment facts: {@code enrolled}, the device-owner
     * DPC package ({@code dpc_package}, "com.hmdm.launcher"), the Headwind server the phone
     * reports to ({@code headwind_url}), how ownership was set ({@code set_via},
     * "adb-device-owner"), and when ({@code enrolled_at}). When mdm-enroll never ran the
     * wizard emits {@code enrolled:false} with {@code ""} for every other fact (the jq
     * blank-not-omit convention) — {@code enrolled_at:""} binds to a null {@link Instant}
     * exactly like the top-level timestamps. {@code enrolled} is a BOXED Boolean for the
     * same reason as {@code EnterpriseProfile.present}: Jackson 3's record binding 400s an
     * omitted primitive component, and a producer omitting the flag must not break ingest.
     * Absent/null folds to {@code false} in the service.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Mdm(
            @Nullable
            Boolean enrolled,

            @JsonProperty("dpc_package")
            @Size(max = 253, message = "dpc_package is too long")
            @Nullable
            String dpcPackage,

            @JsonProperty("headwind_url")
            @Size(max = 512, message = "headwind_url is too long")
            @Nullable
            String headwindUrl,

            @JsonProperty("set_via")
            @Size(max = 64, message = "set_via is too long")
            @Nullable
            String setVia,

            @JsonProperty("enrolled_at")
            @Nullable
            Instant enrolledAt) {
    }
}
