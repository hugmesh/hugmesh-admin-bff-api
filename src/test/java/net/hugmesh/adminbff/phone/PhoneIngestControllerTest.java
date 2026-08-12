package net.hugmesh.adminbff.phone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.adminbff.web.dto.PhoneIngestRequest;
import net.hugmesh.commons.security.DomainRegistry;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The phone-ingest acceptance bar — proves the channel is mTLS-shaped (NO JWT), binds the
 * wizard's REAL snake_case {@code phone-ingest/v1} AND {@code v2} shapes (v2 = v1 + the
 * additive {@code mdm} object; a v1 record binds a null {@code mdm}), and fails closed on
 * anything that is not a phone record (including a schema revision this BFF does not
 * know, e.g. v3).
 *
 * <ul>
 *   <li><b>NO CASDOOR JWT REQUIRED: a POST of a real wizard payload with no Casdoor token is
 *       accepted</b> — {@code /bff/internal/**} is gated to {@code ROLE_SERVICE}, which the
 *       wizard satisfies with {@code X-Internal-Token}; this slice leaves the credential
 *       UNARMED (dev/test parity). Armed matrix: {@code InternalSurfaceRoleMatrixTest}.</li>
 *   <li><b>snake_case binds</b>: {@code device_id}/{@code os_version}/{@code tailscale_ip}/
 *       nested {@code enterprise_profile.user_id} arrive on the DTO (a camelCase-shaped DTO
 *       would silently null them — this is the regression net).</li>
 *   <li><b>Blank-vs-absent</b>: the wizard emits {@code ""} for absent facts —
 *       {@code enrolled_at:""} binds to a null {@link Instant}, not a 400.</li>
 *   <li><b>Fail-closed contract</b>: blank device_id / wrong schema / non-phone
 *       device_class are clean 400s that NEVER write; unknown additive keys are ignored.</li>
 *   <li>The ACK is minimal (accepted + the caller's own ingest count).</li>
 * </ul>
 */
@WebFluxTest(controllers = PhoneIngestController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class PhoneIngestControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean PhoneDeviceService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static PhoneDevice row(String deviceId, long count) {
        return new PhoneDevice("pd-1", deviceId, "phone", "1C291FDF3005A", "oriole",
                "Pixel 6", "GrapheneOS", "2026071400", "hugmesh.internal",
                "https://headscale.hugmesh.internal", "100.64.0.7",
                "phone-1c291fdf3005a", "user", "acme.hugmesh.systems", true, 10L,
                "vault-seed", true, "com.hmdm.launcher",
                "https://headwind.hugmesh.internal", "adb-device-owner",
                Instant.parse("2026-07-14T11:58:00Z"),
                "https://attestation.hugmesh.systems",
                "net.hugmesh.auditor", "operator-paired",
                Instant.parse("2026-07-14T12:00:00Z"), Instant.parse("2026-07-14T12:05:00Z"),
                Instant.now(), Instant.now(), count,
                "unmanaged", "unlocked", null, 0L, null, null, null, null, null, "headwind", null);
    }

    /** The REAL wizard shape — jq snake_case, exactly as cmd_ingest emits it. */
    private static final String WIZARD_BODY = """
            {"schema":"phone-ingest/v1","device_id":"phone-1c291fdf3005a",
             "device_class":"phone","serial":"1C291FDF3005A","codename":"oriole",
             "marketing_name":"Pixel 6","os":"GrapheneOS","os_version":"2026071400",
             "superdomain":"hugmesh.internal",
             "login_server":"https://headscale.hugmesh.internal",
             "tailscale_ip":"100.64.0.7","tailscale_hostname":"phone-1c291fdf3005a",
             "role":"user","attached_domain":"acme.hugmesh.systems",
             "enterprise_profile":{"present":true,"user_id":10,"credential_custody":"vault-seed"},
             "attestation_url":"https://attestation.hugmesh.systems",
             "auditor_package":"net.hugmesh.auditor",
             "attestation_verdict":"operator-paired",
             "enrolled_at":"2026-07-14T12:00:00Z","generated_at":"2026-07-14T12:05:00Z"}""";

    @Test
    void ingest_noJwt_isAccepted_andSnakeCaseBinds() {
        when(service.ingest(any())).thenReturn(Mono.just(row("phone-1c291fdf3005a", 1L)));
        // NO .mutateWith(mockJwt()) — no Casdoor token, exactly as the wizard presents (mTLS +
        // X-Internal-Token). /bff/internal/** is ROLE_SERVICE; this slice configures no
        // app.internal.token, the UNARMED dev/test parity branch (see InternalSurfaceRoleMatrixTest).
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(WIZARD_BODY)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.accepted").isEqualTo(true)
                .jsonPath("$.ingestCount").isEqualTo(1);
        // The snake_case keys actually LANDED on the DTO (the whole point of the
        // per-field @JsonProperty mapping — a silent-null bind would pass a vacuous 200).
        // EVERY multi-word (@JsonProperty-mapped) field is asserted — dropping any single
        // annotation nulls exactly one assertion below (the single-word fields bind by
        // Jackson default and are covered by the deviceId/serial/codename/os spot checks).
        ArgumentCaptor<PhoneIngestRequest> cap = ArgumentCaptor.forClass(PhoneIngestRequest.class);
        verify(service).ingest(cap.capture());
        PhoneIngestRequest b = cap.getValue();
        assertThat(b.deviceId()).isEqualTo("phone-1c291fdf3005a");
        assertThat(b.deviceClass()).isEqualTo("phone");
        assertThat(b.serial()).isEqualTo("1C291FDF3005A");
        assertThat(b.codename()).isEqualTo("oriole");
        assertThat(b.marketingName()).isEqualTo("Pixel 6");
        assertThat(b.os()).isEqualTo("GrapheneOS");
        assertThat(b.osVersion()).isEqualTo("2026071400");
        assertThat(b.superdomain()).isEqualTo("hugmesh.internal");
        assertThat(b.loginServer()).isEqualTo("https://headscale.hugmesh.internal");
        assertThat(b.tailscaleIp()).isEqualTo("100.64.0.7");
        assertThat(b.tailscaleHostname()).isEqualTo("phone-1c291fdf3005a");
        assertThat(b.role()).isEqualTo("user");
        assertThat(b.attachedDomain()).isEqualTo("acme.hugmesh.systems");
        assertThat(b.enterpriseProfile()).isNotNull();
        assertThat(b.enterpriseProfile().present()).isTrue();
        assertThat(b.enterpriseProfile().userId()).isEqualTo(10L);
        assertThat(b.enterpriseProfile().credentialCustody()).isEqualTo("vault-seed");
        assertThat(b.attestationUrl()).isEqualTo("https://attestation.hugmesh.systems");
        assertThat(b.auditorPackage()).isEqualTo("net.hugmesh.auditor");
        assertThat(b.attestationVerdict()).isEqualTo("operator-paired");
        assertThat(b.enrolledAt()).isEqualTo(Instant.parse("2026-07-14T12:00:00Z"));
        assertThat(b.generatedAt()).isEqualTo(Instant.parse("2026-07-14T12:05:00Z"));
        // A v1 record has NO mdm key at all — the additive v2 object binds null (the
        // service flattens that to mdm_enrolled=false + null facts).
        assertThat(b.mdm()).isNull();
    }

    /** The REAL v2 wizard shape — v1 unchanged + the additive mdm object. */
    private static final String WIZARD_BODY_V2 = """
            {"schema":"phone-ingest/v2","device_id":"phone-1c291fdf3005a",
             "device_class":"phone","serial":"1C291FDF3005A","codename":"oriole",
             "marketing_name":"Pixel 6","os":"GrapheneOS","os_version":"2026071400",
             "superdomain":"hugmesh.internal",
             "login_server":"https://headscale.hugmesh.internal",
             "tailscale_ip":"100.64.0.7","tailscale_hostname":"phone-1c291fdf3005a",
             "role":"user","attached_domain":"acme.hugmesh.systems",
             "enterprise_profile":{"present":true,"user_id":10,"credential_custody":"vault-seed"},
             "mdm":{"enrolled":true,"dpc_package":"com.hmdm.launcher",
              "headwind_url":"https://headwind.hugmesh.internal",
              "set_via":"adb-device-owner","enrolled_at":"2026-07-14T11:58:00Z"},
             "attestation_url":"https://attestation.hugmesh.systems",
             "auditor_package":"net.hugmesh.auditor",
             "attestation_verdict":"operator-paired",
             "enrolled_at":"2026-07-14T12:00:00Z","generated_at":"2026-07-14T12:05:00Z"}""";

    @Test
    void ingestV2_noJwt_isAccepted_everyMdmFieldBinds() {
        when(service.ingest(any())).thenReturn(Mono.just(row("phone-1c291fdf3005a", 1L)));
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(WIZARD_BODY_V2)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.accepted").isEqualTo(true)
                .jsonPath("$.ingestCount").isEqualTo(1);
        // EVERY mdm component is asserted (all snake_case keys are @JsonProperty-mapped —
        // dropping any single annotation nulls exactly one assertion below), plus v1 spot
        // checks proving the additive object changed nothing about the v1 binding.
        ArgumentCaptor<PhoneIngestRequest> cap = ArgumentCaptor.forClass(PhoneIngestRequest.class);
        verify(service).ingest(cap.capture());
        PhoneIngestRequest b = cap.getValue();
        assertThat(b.schema()).isEqualTo("phone-ingest/v2");
        assertThat(b.deviceId()).isEqualTo("phone-1c291fdf3005a");
        assertThat(b.enterpriseProfile().present()).isTrue();
        assertThat(b.mdm()).isNotNull();
        assertThat(b.mdm().enrolled()).isTrue();
        assertThat(b.mdm().dpcPackage()).isEqualTo("com.hmdm.launcher");
        assertThat(b.mdm().headwindUrl()).isEqualTo("https://headwind.hugmesh.internal");
        assertThat(b.mdm().setVia()).isEqualTo("adb-device-owner");
        assertThat(b.mdm().enrolledAt()).isEqualTo(Instant.parse("2026-07-14T11:58:00Z"));
        assertThat(b.enrolledAt()).isEqualTo(Instant.parse("2026-07-14T12:00:00Z"));
    }

    @Test
    void ingestV2_mdmEnrolledKeyOmitted_bindsNull_notBadRequest() {
        when(service.ingest(any())).thenReturn(Mono.just(row("phone-noflag2", 1L)));
        // The mdm object arrives WITHOUT its `enrolled` key — the boxed Boolean binds
        // null (Jackson 3 would 400 an omitted primitive record component), and the
        // SERVICE folds null -> false (PhoneDeviceServiceTest pins that fold).
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"phone-ingest/v2\",\"device_id\":\"phone-noflag2\","
                        + "\"device_class\":\"phone\","
                        + "\"mdm\":{\"dpc_package\":\"com.hmdm.launcher\"}}")
                .exchange().expectStatus().isOk();
        ArgumentCaptor<PhoneIngestRequest> cap = ArgumentCaptor.forClass(PhoneIngestRequest.class);
        verify(service).ingest(cap.capture());
        assertThat(cap.getValue().mdm()).isNotNull();
        assertThat(cap.getValue().mdm().enrolled()).isNull();
        assertThat(cap.getValue().mdm().dpcPackage()).isEqualTo("com.hmdm.launcher");
    }

    @Test
    void ingestV2_mdmNeverRanBlanks_bindNullInstant_notBadRequest() {
        when(service.ingest(any())).thenReturn(Mono.just(row("phone-nomdm", 1L)));
        // The exact shape the wizard emits when mdm-enroll never ran: enrolled:false and
        // "" for every other fact (the jq blank-not-omit convention) — mdm.enrolled_at:""
        // must bind a null Instant exactly like the top-level timestamps.
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"phone-ingest/v2\",\"device_id\":\"phone-nomdm\","
                        + "\"device_class\":\"phone\","
                        + "\"mdm\":{\"enrolled\":false,\"dpc_package\":\"\","
                        + "\"headwind_url\":\"\",\"set_via\":\"\",\"enrolled_at\":\"\"}}")
                .exchange().expectStatus().isOk();
        ArgumentCaptor<PhoneIngestRequest> cap = ArgumentCaptor.forClass(PhoneIngestRequest.class);
        verify(service).ingest(cap.capture());
        assertThat(cap.getValue().mdm().enrolled()).isFalse();
        assertThat(cap.getValue().mdm().enrolledAt()).isNull();   // "" -> null Instant
        assertThat(cap.getValue().mdm().dpcPackage()).isEmpty();  // "" survives to the service trim
    }

    @Test
    void ingest_mdmProviderAndIntuneId_bindSnakeCase() {
        when(service.ingest(any())).thenReturn(Mono.just(row("phone-azure", 1L)));
        // An azure-intune enrolment: the two changeset-307 snake_case fields must bind onto
        // the DTO (a camelCase-shaped field would silently null them).
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"phone-ingest/v2\",\"device_id\":\"phone-azure\","
                        + "\"device_class\":\"phone\","
                        + "\"mdm_provider\":\"azure-intune\","
                        + "\"intune_device_id\":\"intune-managed-id-42\"}")
                .exchange().expectStatus().isOk();
        ArgumentCaptor<PhoneIngestRequest> cap = ArgumentCaptor.forClass(PhoneIngestRequest.class);
        verify(service).ingest(cap.capture());
        assertThat(cap.getValue().mdmProvider()).isEqualTo("azure-intune");
        assertThat(cap.getValue().intuneDeviceId()).isEqualTo("intune-managed-id-42");
    }

    @Test
    void ingest_v1Body_noProviderField_bindsNull_serviceDefaultsHeadwind() {
        when(service.ingest(any())).thenReturn(Mono.just(row("phone-v1", 1L)));
        // A v1 body has no mdm_provider key at all — it binds null on the DTO; the SERVICE
        // folds null -> 'headwind' (PhoneDeviceServiceTest pins that default). Additive: a v1
        // body is accepted unchanged (the schema stays phone-ingest/v2, still binds v1).
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"phone-ingest/v1\",\"device_id\":\"phone-v1\","
                        + "\"device_class\":\"phone\"}")
                .exchange().expectStatus().isOk();
        ArgumentCaptor<PhoneIngestRequest> cap = ArgumentCaptor.forClass(PhoneIngestRequest.class);
        verify(service).ingest(cap.capture());
        assertThat(cap.getValue().mdmProvider()).isNull();       // no field on a v1 body
        assertThat(cap.getValue().intuneDeviceId()).isNull();
    }

    @Test
    void ingest_bogusProvider_isBadRequest_andNeverWrites() {
        // The @Pattern pins headwind|azure-intune (or blank) — a spoofed value is a clean 400.
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"phone-ingest/v2\",\"device_id\":\"phone-bogus\","
                        + "\"device_class\":\"phone\",\"mdm_provider\":\"jamf\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).ingest(any());
    }

    @Test
    void ingestV3Schema_isBadRequest_andNeverWrites() {
        // The discriminator admits EXACTLY v1|v2 — a hypothetical v3 fails closed until
        // this DTO learns its shape.
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"phone-ingest/v3\",\"device_id\":\"phone-x\",\"device_class\":\"phone\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).ingest(any());
    }

    @Test
    void ingest_enterpriseProfileOmittedEntirely_bindsNullProfile_ok() {
        when(service.ingest(any())).thenReturn(Mono.just(row("phone-min", 1L)));
        // The nested object itself absent (not just its keys): the DTO must bind a null
        // profile — the service derives present=false from it.
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"phone-ingest/v1\",\"device_id\":\"phone-min\","
                        + "\"device_class\":\"phone\"}")
                .exchange().expectStatus().isOk();
        ArgumentCaptor<PhoneIngestRequest> cap = ArgumentCaptor.forClass(PhoneIngestRequest.class);
        verify(service).ingest(cap.capture());
        assertThat(cap.getValue().enterpriseProfile()).isNull();
    }

    @Test
    void ingest_enterpriseProfilePresentKeyOmitted_bindsNull_notBadRequest() {
        when(service.ingest(any())).thenReturn(Mono.just(row("phone-noflag", 1L)));
        // The profile object arrives WITHOUT its `present` key. Jackson 3's record
        // binding 400s an omitted PRIMITIVE component (empirically — the legacy
        // FAIL_ON_NULL_FOR_PRIMITIVES leniency does not reach it), which is exactly why
        // the DTO types it as a boxed Boolean: the omitted key binds null here, and the
        // SERVICE folds null -> false (PhoneDeviceServiceTest pins that fold).
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"phone-ingest/v1\",\"device_id\":\"phone-noflag\","
                        + "\"device_class\":\"phone\","
                        + "\"enterprise_profile\":{\"user_id\":7}}")
                .exchange().expectStatus().isOk();
        ArgumentCaptor<PhoneIngestRequest> cap = ArgumentCaptor.forClass(PhoneIngestRequest.class);
        verify(service).ingest(cap.capture());
        assertThat(cap.getValue().enterpriseProfile()).isNotNull();
        assertThat(cap.getValue().enterpriseProfile().present()).isNull();
        assertThat(cap.getValue().enterpriseProfile().userId()).isEqualTo(7L);
    }

    @Test
    void ingest_blankAbsentFacts_bindNullInstants_notBadRequest() {
        when(service.ingest(any())).thenReturn(Mono.just(row("phone-nousb", 1L)));
        // A no-USB operator-attested record: the wizard's jq emits "" (never omits keys)
        // for the facts it could not probe — including the two timestamps.
        String noUsb = """
                {"schema":"phone-ingest/v1","device_id":"phone-nousb","device_class":"phone",
                 "serial":"","codename":"oriole","marketing_name":"Pixel 6","os":"unknown",
                 "os_version":"","superdomain":"hugmesh.internal","login_server":"",
                 "tailscale_ip":"","tailscale_hostname":"","role":"user","attached_domain":"",
                 "enterprise_profile":{"present":false,"user_id":null,"credential_custody":""},
                 "attestation_url":"","auditor_package":"","attestation_verdict":"",
                 "enrolled_at":"","generated_at":"2026-07-14T12:05:00Z"}""";
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(noUsb)
                .exchange().expectStatus().isOk();
        ArgumentCaptor<PhoneIngestRequest> cap = ArgumentCaptor.forClass(PhoneIngestRequest.class);
        verify(service).ingest(cap.capture());
        assertThat(cap.getValue().enrolledAt()).isNull();       // "" -> null Instant
        assertThat(cap.getValue().generatedAt())
                .isEqualTo(Instant.parse("2026-07-14T12:05:00Z"));
        assertThat(cap.getValue().enterpriseProfile().userId()).isNull();
    }

    @Test
    void ingest_blankDeviceId_isBadRequest_andNeverWrites() {
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"phone-ingest/v1\",\"device_id\":\"\",\"device_class\":\"phone\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).ingest(any());
    }

    @Test
    void ingest_wrongSchema_isBadRequest_andNeverWrites() {
        // A node self-report (or any other record family) POSTed here fails closed — the
        // mirror image of the self-report route rejecting phone records.
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"node-self-report/v1\",\"device_id\":\"phone-x\",\"device_class\":\"phone\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).ingest(any());
    }

    @Test
    void ingest_nonPhoneDeviceClass_isBadRequest_andNeverWrites() {
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"phone-ingest/v1\",\"device_id\":\"node-7\",\"device_class\":\"node\"}")
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).ingest(any());
    }

    @Test
    void ingest_unknownAdditiveKey_isIgnored_forwardCompatible() {
        when(service.ingest(any())).thenReturn(Mono.just(row("phone-fwd", 1L)));
        // A future wizard adds a field — today's BFF must not reject the record.
        web.post().uri("/bff/internal/device-registry/phone-ingest")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"schema\":\"phone-ingest/v1\",\"device_id\":\"phone-fwd\","
                        + "\"device_class\":\"phone\",\"some_future_field\":\"x\"}")
                .exchange().expectStatus().isOk();
        verify(service).ingest(any());
    }
}
