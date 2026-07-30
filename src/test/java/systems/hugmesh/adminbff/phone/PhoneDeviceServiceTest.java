package systems.hugmesh.adminbff.phone;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.web.dto.PhoneIngestRequest;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The service's NORMALIZATION contract, pinned at the seam the wire DTO cannot express:
 * <ul>
 *   <li>a null / present-less enterprise_profile folds to {@code present=false} (the boxed
 *       Boolean exists because Jackson 3 400s an omitted primitive record component — the
 *       controller slice proves the null bind; this proves the fold), and the v2
 *       {@code mdm} object folds identically ({@code enrolled} null/absent-object →
 *       {@code false});</li>
 *   <li>the wizard's {@code ""} emissions become real NULLs before persisting (never
 *       empty-string look-alike rows) — including the mdm never-ran all-blank shape;</li>
 *   <li>identity fields are trimmed, not nulled.</li>
 * </ul>
 */
class PhoneDeviceServiceTest {

    private final PhoneDeviceRepository repo = mock(PhoneDeviceRepository.class);
    private final PhoneDeviceService service = new PhoneDeviceService(repo);

    private static PhoneDevice anyRow() {
        return new PhoneDevice("pd-1", "phone-x", "phone", null, "oriole", null, null, null,
                null, null, null, null, null, null, false, null, null, false, null, null,
                null, null, null, null, null, null, null, Instant.now(), Instant.now(), 1L,
                "unmanaged", "unlocked", null, 0L, null, null, null, null, null, "headwind", null);
    }

    @Test
    void nullPresentInProfile_foldsToFalse_userIdKept() {
        when(repo.upsert(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.just(anyRow()));
        PhoneIngestRequest b = new PhoneIngestRequest("phone-ingest/v1", "phone-x", "phone",
                null, "oriole", null, null, null, null, null, null, null, null, null,
                new PhoneIngestRequest.EnterpriseProfile(null, 7L, "vault-seed"),
                null, null, null, null, null, null, null, null);
        service.ingest(b).block();
        ArgumentCaptor<PhoneIngest> cap = ArgumentCaptor.forClass(PhoneIngest.class);
        verify(repo).upsert(cap.capture());
        assertThat(cap.getValue().enterpriseProfilePresent()).isFalse();
        assertThat(cap.getValue().enterpriseProfileUserId()).isEqualTo(7L);
        assertThat(cap.getValue().enterpriseProfileCredentialCustody()).isEqualTo("vault-seed");
        // A v1 record (no mdm object) flattens to enrolled=false + null mdm facts.
        assertThat(cap.getValue().mdmEnrolled()).isFalse();
        assertThat(cap.getValue().mdmDpcPackage()).isNull();
        assertThat(cap.getValue().mdmEnrolledAt()).isNull();
    }

    @Test
    void nullEnrolledInMdm_foldsToFalse_factsKept() {
        when(repo.upsert(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.just(anyRow()));
        // The mdm mirror of the present-less profile: a producer omitting the flag must
        // fold to false while the reported facts survive (trimmed).
        PhoneIngestRequest b = new PhoneIngestRequest("phone-ingest/v2", "phone-x", "phone",
                null, "oriole", null, null, null, null, null, null, null, null, null, null,
                new PhoneIngestRequest.Mdm(null, "  com.hmdm.launcher  ",
                        "https://headwind.hugmesh.internal", "adb-device-owner",
                        Instant.parse("2026-07-14T11:58:00Z")),
                null, null, null, null, null, null, null);
        service.ingest(b).block();
        ArgumentCaptor<PhoneIngest> cap = ArgumentCaptor.forClass(PhoneIngest.class);
        verify(repo).upsert(cap.capture());
        assertThat(cap.getValue().mdmEnrolled()).isFalse();
        assertThat(cap.getValue().mdmDpcPackage()).isEqualTo("com.hmdm.launcher");
        assertThat(cap.getValue().mdmHeadwindUrl())
                .isEqualTo("https://headwind.hugmesh.internal");
        assertThat(cap.getValue().mdmSetVia()).isEqualTo("adb-device-owner");
        assertThat(cap.getValue().mdmEnrolledAt())
                .isEqualTo(Instant.parse("2026-07-14T11:58:00Z"));
    }

    @Test
    void wizardBlankEmissions_becomeRealNulls_identityTrimmedNotNulled() {
        when(repo.upsert(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.just(anyRow()));
        PhoneIngestRequest b = new PhoneIngestRequest("phone-ingest/v2", "  phone-x  ",
                "phone", "", "oriole", "  ", "", "", "", "", "", "", "", "",
                new PhoneIngestRequest.EnterpriseProfile(Boolean.TRUE, null, ""),
                // The mdm never-ran shape: enrolled:false + "" for every other fact.
                new PhoneIngestRequest.Mdm(Boolean.FALSE, "", "  ", "", null),
                "", "", "", null, null, null, null);
        service.ingest(b).block();
        ArgumentCaptor<PhoneIngest> cap = ArgumentCaptor.forClass(PhoneIngest.class);
        verify(repo).upsert(cap.capture());
        PhoneIngest r = cap.getValue();
        assertThat(r.deviceId()).isEqualTo("phone-x");         // trimmed, kept
        assertThat(r.serial()).isNull();                        // "" -> null
        assertThat(r.marketingName()).isNull();                 // "  " -> null
        assertThat(r.tailscaleIp()).isNull();
        assertThat(r.enterpriseProfilePresent()).isTrue();
        assertThat(r.enterpriseProfileCredentialCustody()).isNull();
        assertThat(r.mdmEnrolled()).isFalse();
        assertThat(r.mdmDpcPackage()).isNull();                 // "" -> null
        assertThat(r.mdmHeadwindUrl()).isNull();                // "  " -> null
        assertThat(r.mdmSetVia()).isNull();
        assertThat(r.attestationVerdict()).isNull();
    }

    @Test
    void v1Body_noProvider_foldsToHeadwind_intuneIdNull() {
        when(repo.upsert(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.just(anyRow()));
        // A v1 body carries no mdm_provider field at all (null) — it MUST fold to the
        // sovereign 'headwind' default so the NOT-NULL column always gets a value.
        PhoneIngestRequest b = new PhoneIngestRequest("phone-ingest/v1", "phone-x", "phone",
                null, "oriole", null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null);
        service.ingest(b).block();
        ArgumentCaptor<PhoneIngest> cap = ArgumentCaptor.forClass(PhoneIngest.class);
        verify(repo).upsert(cap.capture());
        assertThat(cap.getValue().mdmProvider()).isEqualTo("headwind");
        assertThat(cap.getValue().intuneDeviceId()).isNull();
    }

    @Test
    void azureBody_providerAndIntuneIdPersist_blankIntuneTrimsToNull() {
        when(repo.upsert(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.just(anyRow()));
        // An azure-intune enrolment reports the provider + the Graph managedDevice id.
        PhoneIngestRequest b = new PhoneIngestRequest("phone-ingest/v2", "phone-x", "phone",
                null, "oriole", null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null,
                "azure-intune", "  8f14e45f-ea-managed-device-id  ");
        service.ingest(b).block();
        ArgumentCaptor<PhoneIngest> cap = ArgumentCaptor.forClass(PhoneIngest.class);
        verify(repo).upsert(cap.capture());
        assertThat(cap.getValue().mdmProvider()).isEqualTo("azure-intune");
        // intune_device_id is trimmed (like every optional string) but kept.
        assertThat(cap.getValue().intuneDeviceId()).isEqualTo("8f14e45f-ea-managed-device-id");
    }

    @Test
    void blankProvider_foldsToHeadwind() {
        when(repo.upsert(org.mockito.ArgumentMatchers.any())).thenReturn(Mono.just(anyRow()));
        // An explicit "" (the jq blank-not-omit convention) must also fold to 'headwind'.
        PhoneIngestRequest b = new PhoneIngestRequest("phone-ingest/v2", "phone-x", "phone",
                null, "oriole", null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, "", "");
        service.ingest(b).block();
        ArgumentCaptor<PhoneIngest> cap = ArgumentCaptor.forClass(PhoneIngest.class);
        verify(repo).upsert(cap.capture());
        assertThat(cap.getValue().mdmProvider()).isEqualTo("headwind");
        assertThat(cap.getValue().intuneDeviceId()).isNull();
    }
}
