package systems.hugmesh.adminbff.phone;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code phone_device} (Liquibase changesets 302 + 303 + 304) — the durable shape
 * for a {@link PhoneDevice}. PK is a {@code varchar(36)} DB-generated UUID string;
 * {@code device_id} is UNIQUE. {@link PhoneDevice} stays the domain record;
 * {@link PhoneDeviceRepository} maps between the two. Mirrors
 * {@link systems.hugmesh.adminbff.device.DeviceEnrollmentRow}, including its
 * {@link Persistable}/{@code isNew} plumbing — retained for row-pattern parity, but NOT on
 * the write path here: the first-ingest INSERT is the hand-written
 * {@code INSERT ... RETURNING id} (Spring Data cannot generate string PKs), so
 * {@code save()} is never called on this type.
 *
 * <p>The trailing seven columns (changeset 304) are OPERATOR-AUTHORITATIVE management + lock
 * state, and the last two ({@code physical_owner}, {@code owner_domain}, changeset 305) are
 * the OPERATOR-AUTHORITATIVE fleet-ownership discriminators. They surface on the fleet READS
 * (this entity is mapped whole by the derived finders), but the ingest INSERT + REFRESH
 * ({@link PhoneDeviceRowRepository}) deliberately OMIT them, so a re-ingest never overwrites
 * managed/locked status OR the assigned owner; they are mutated ONLY by the SUPERADMIN-plane
 * CAS / owner-assignment queries.
 *
 * <p>The final two columns ({@code mdm_provider}, {@code intune_device_id}, changeset 307) are
 * by contrast DEVICE-REPORTED telemetry (like the 303 {@code mdm_*} facts), so the ingest
 * INSERT + REFRESH DO write them — they are advisory self-report, never operator authority.
 */
@Table("phone_device")
public record PhoneDeviceRow(
        @Id @Column("id") String id,
        @Column("device_id") String deviceId,
        @Column("device_class") String deviceClass,
        @Column("serial") String serial,
        @Column("codename") String codename,
        @Column("marketing_name") String marketingName,
        @Column("os") String os,
        @Column("os_version") String osVersion,
        @Column("superdomain") String superdomain,
        @Column("login_server") String loginServer,
        @Column("tailscale_ip") String tailscaleIp,
        @Column("tailscale_hostname") String tailscaleHostname,
        @Column("role") String role,
        @Column("attached_domain") String attachedDomain,
        @Column("enterprise_profile_present") boolean enterpriseProfilePresent,
        @Column("enterprise_profile_user_id") Long enterpriseProfileUserId,
        @Column("enterprise_profile_credential_custody") String enterpriseProfileCredentialCustody,
        @Column("mdm_enrolled") boolean mdmEnrolled,
        @Column("mdm_dpc_package") String mdmDpcPackage,
        @Column("mdm_headwind_url") String mdmHeadwindUrl,
        @Column("mdm_set_via") String mdmSetVia,
        @Column("mdm_enrolled_at") Instant mdmEnrolledAt,
        @Column("attestation_url") String attestationUrl,
        @Column("auditor_package") String auditorPackage,
        @Column("attestation_verdict") String attestationVerdict,
        @Column("enrolled_at") Instant enrolledAt,
        @Column("generated_at") Instant generatedAt,
        @Column("first_ingested_at") Instant firstIngestedAt,
        @Column("last_ingested_at") Instant lastIngestedAt,
        @Column("ingest_count") long ingestCount,
        @Column("management_mode") String managementMode,
        @Column("lock_state") String lockState,
        @Column("lock_propagation_state") String lockPropagationState,
        @Column("lock_generation") long lockGeneration,
        @Column("lock_reason") String lockReason,
        @Column("lock_actor") String lockActor,
        @Column("lock_updated_at") Instant lockUpdatedAt,
        @Column("physical_owner") String physicalOwner,
        @Column("owner_domain") String ownerDomain,
        @Column("mdm_provider") String mdmProvider,
        @Column("intune_device_id") String intuneDeviceId,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public PhoneDeviceRow(String id, String deviceId, String deviceClass, String serial,
                          String codename, String marketingName, String os, String osVersion,
                          String superdomain, String loginServer, String tailscaleIp,
                          String tailscaleHostname, String role, String attachedDomain,
                          boolean enterpriseProfilePresent, Long enterpriseProfileUserId,
                          String enterpriseProfileCredentialCustody, boolean mdmEnrolled,
                          String mdmDpcPackage, String mdmHeadwindUrl, String mdmSetVia,
                          Instant mdmEnrolledAt, String attestationUrl,
                          String auditorPackage, String attestationVerdict, Instant enrolledAt,
                          Instant generatedAt, Instant firstIngestedAt, Instant lastIngestedAt,
                          long ingestCount, String managementMode, String lockState,
                          String lockPropagationState, long lockGeneration, String lockReason,
                          String lockActor, Instant lockUpdatedAt, String physicalOwner,
                          String ownerDomain, String mdmProvider, String intuneDeviceId) {
        this(id, deviceId, deviceClass, serial, codename, marketingName, os, osVersion,
                superdomain, loginServer, tailscaleIp, tailscaleHostname, role, attachedDomain,
                enterpriseProfilePresent, enterpriseProfileUserId, enterpriseProfileCredentialCustody,
                mdmEnrolled, mdmDpcPackage, mdmHeadwindUrl, mdmSetVia, mdmEnrolledAt,
                attestationUrl, auditorPackage, attestationVerdict, enrolledAt, generatedAt,
                firstIngestedAt, lastIngestedAt, ingestCount, managementMode, lockState,
                lockPropagationState, lockGeneration, lockReason, lockActor, lockUpdatedAt,
                physicalOwner, ownerDomain, mdmProvider, intuneDeviceId, false);
    }

    PhoneDevice toDomain() {
        return new PhoneDevice(id, deviceId, deviceClass, serial, codename, marketingName, os,
                osVersion, superdomain, loginServer, tailscaleIp, tailscaleHostname, role,
                attachedDomain, enterpriseProfilePresent, enterpriseProfileUserId,
                enterpriseProfileCredentialCustody, mdmEnrolled, mdmDpcPackage, mdmHeadwindUrl,
                mdmSetVia, mdmEnrolledAt, attestationUrl, auditorPackage,
                attestationVerdict, enrolledAt, generatedAt, firstIngestedAt, lastIngestedAt,
                ingestCount, managementMode, lockState, lockPropagationState, lockGeneration,
                lockReason, lockActor, lockUpdatedAt, physicalOwner, ownerDomain,
                mdmProvider, intuneDeviceId);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
