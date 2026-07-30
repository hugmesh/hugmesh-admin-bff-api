package systems.hugmesh.adminbff.radio;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.config.SecurityConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.web.ApiExceptionHandler;
import systems.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The NODE RADIO controller role + error-mapping matrix on
 * {@code /bff/admin/device-radios}. Mirrors {@code StoragePoolControllerTest}
 * ({@code @WebFluxTest} + the real {@link SecurityConfig}), KEEPING the DELIBERATE
 * DIVERGENCE that radios are ADMIN-CAPABLE: an ADMIN may reach AND mutate the path (the
 * OWNERSHIP ALLOW/DENY matrix is the downstream service wall, exercised in
 * {@link NodeRadioServiceTest}). Proves:
 * <ul>
 *   <li>ADMIN + SUPERADMIN read/write ALLOW at the path gate;</li>
 *   <li>MOD / USER DENY (403) on read AND write, never reaching the service;</li>
 *   <li>a service DENY ({@link RadioAccessDeniedException}) maps to 403;</li>
 *   <li>a service mixed-shape / unknown-node ({@link IllegalArgumentException}) maps to
 *       422;</li>
 *   <li>a malformed body (no radioId / bad meshChannel / bad serialPath / bad
 *       gatewayNodeId) is a 400, never a write;</li>
 *   <li>the signed export is SUPERADMIN | internal-mTLS only.</li>
 * </ul>
 */
@WebFluxTest(controllers = RadioDeviceController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class RadioDeviceControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean NodeRadioService radios;
    @MockitoBean NodeRadioExportService export;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static RadioDevice serialSample() {
        return new RadioDevice("radio-1", "dev-1", RadioDevice.TRANSPORT_SERIAL, "/dev/ttyUSB0",
                null, null, null, null, null, "lora-0", 0, RadioDevice.STATE_ACTIVE, "brandx",
                RadioDevice.PROP_PENDING, 1L, "alice@brandx", Instant.now(), null, null);
    }

    private static RadioDevice mqttSample() {
        return new RadioDevice("radio-2", "dev-1", RadioDevice.TRANSPORT_MQTT, null,
                "mqtt.example.org", 1883, "msh/US", "LongFast", "!0a1b2c3d", "wan-0", 1,
                RadioDevice.STATE_ACTIVE, "brandx", RadioDevice.PROP_PENDING, 2L,
                "alice@brandx", Instant.now(), null, null);
    }

    private static final String SERIAL_BODY =
            "{\"transport\":\"serial\",\"serialPath\":\"/dev/ttyUSB0\","
            + "\"radioId\":\"lora-0\",\"meshChannel\":0}";

    private static final String MQTT_BODY =
            "{\"transport\":\"mqtt\",\"host\":\"mqtt.example.org\",\"port\":1883,"
            + "\"topicRoot\":\"msh/US\",\"channelName\":\"LongFast\","
            + "\"gatewayNodeId\":\"!0a1b2c3d\",\"radioId\":\"wan-0\",\"meshChannel\":1}";

    /** The attachRadio stub matcher (any well-formed argument set). */
    private org.mockito.stubbing.OngoingStubbing<Mono<RadioDevice>> whenAttach() {
        return when(radios.attachRadio(anyString(), anyString(), any(), any(), any(), any(),
                any(), any(), anyString(), anyInt(), any(PrincipalDomain.class), anyString()));
    }

    private void verifyNeverAttached() {
        verify(radios, never()).attachRadio(anyString(), anyString(), any(), any(), any(),
                any(), any(), any(), anyString(), anyInt(), any(PrincipalDomain.class), anyString());
    }

    // ── ADMIN + SUPERADMIN read/write ALLOW at the path gate ────────────────────

    @Test
    void list_asAdmin_isAllowed() {
        when(radios.listRadios(any(PrincipalDomain.class))).thenReturn(Flux.just(serialSample()));
        asAdmin().get().uri("/bff/admin/device-radios")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.radios[0].id").isEqualTo("radio-1")
                .jsonPath("$.radios[0].transport").isEqualTo("serial");
    }

    @Test
    void list_asSuperadmin_isAllowed() {
        when(radios.listRadios(any(PrincipalDomain.class))).thenReturn(Flux.just(mqttSample()));
        asSuperadmin().get().uri("/bff/admin/device-radios")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.radios[0].topicRoot").isEqualTo("msh/US");
    }

    @Test
    void attach_asAdmin_isAllowed() {
        whenAttach().thenReturn(Mono.just(serialSample()));
        asAdmin().post().uri("/bff/admin/device-radios/dev-1/radios")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SERIAL_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("radio-1");
        verify(radios).attachRadio(eq("dev-1"), eq("serial"), eq("/dev/ttyUSB0"), any(), any(),
                any(), any(), any(), eq("lora-0"), eq(0), any(PrincipalDomain.class), anyString());
    }

    @Test
    void attach_mqtt_asSuperadmin_isAllowed_andCarriesTheBrokerShape() {
        whenAttach().thenReturn(Mono.just(mqttSample()));
        asSuperadmin().post().uri("/bff/admin/device-radios/dev-1/radios")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(MQTT_BODY)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.transport").isEqualTo("mqtt")
                .jsonPath("$.channelName").isEqualTo("LongFast");
        verify(radios).attachRadio(eq("dev-1"), eq("mqtt"), any(), eq("mqtt.example.org"),
                eq(1883), eq("msh/US"), eq("LongFast"), eq("!0a1b2c3d"), eq("wan-0"), eq(1),
                any(PrincipalDomain.class), anyString());
    }

    @Test
    void detach_asAdmin_isAllowed() {
        when(radios.detachRadio(eq("radio-1"), any(PrincipalDomain.class), anyString()))
                .thenReturn(Mono.just(1L));
        asAdmin().delete().uri("/bff/admin/device-radios/radios/radio-1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.detached").isEqualTo(1);
    }

    // ── MOD / USER DENY (403) on read AND write ─────────────────────────────────

    @Test
    void list_asMod_isForbidden() {
        asMod().get().uri("/bff/admin/device-radios").exchange().expectStatus().isForbidden();
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/admin/device-radios").exchange().expectStatus().isForbidden();
    }

    @Test
    void attach_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/admin/device-radios/dev-1/radios")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SERIAL_BODY)
                .exchange().expectStatus().isForbidden();
        verifyNeverAttached();
    }

    @Test
    void detach_asUser_isForbidden_andNeverWrites() {
        asUser().delete().uri("/bff/admin/device-radios/radios/radio-1")
                .exchange().expectStatus().isForbidden();
        verify(radios, never()).detachRadio(anyString(), any(PrincipalDomain.class), anyString());
    }

    // ── service DENY (RadioAccessDeniedException) -> 403 ────────────────────────

    @Test
    void attach_onSuperadminOwnedNode_byAdmin_is403_fromServiceGate() {
        // The ownership matrix DENY surfaces from the service as a clean 403 {error}.
        whenAttach().thenReturn(Mono.error(new RadioAccessDeniedException(
                "node core is SUPERADMIN-owned — only a SUPERADMIN may manage its radios")));
        asAdmin().post().uri("/bff/admin/device-radios/core/radios")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SERIAL_BODY)
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("SUPERADMIN-owned"));
    }

    // ── service mixed-shape (IllegalArgumentException) -> 422 ───────────────────

    @Test
    void attach_mixedTransportShape_is422_fromServiceGuard() {
        whenAttach().thenReturn(Mono.error(new IllegalArgumentException(
                "serial transport must not carry host/port (mixed transport shape)")));
        asSuperadmin().post().uri("/bff/admin/device-radios/dev-1/radios")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(SERIAL_BODY)
                .exchange().expectStatus().isEqualTo(org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY)
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("mixed transport shape"));
    }

    // ── validation: malformed body is a 400, never a write ──────────────────────

    @Test
    void attach_missingRadioId_isBadRequest_andNeverWrites() {
        asAdmin().post().uri("/bff/admin/device-radios/dev-1/radios")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"transport\":\"serial\",\"serialPath\":\"/dev/ttyUSB0\",\"meshChannel\":0}")
                .exchange().expectStatus().isBadRequest();
        verifyNeverAttached();
    }

    @Test
    void attach_meshChannelOutOfRange_isBadRequest_andNeverWrites() {
        asAdmin().post().uri("/bff/admin/device-radios/dev-1/radios")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"transport\":\"serial\",\"serialPath\":\"/dev/ttyUSB0\","
                        + "\"radioId\":\"lora-0\",\"meshChannel\":8}")
                .exchange().expectStatus().isBadRequest();
        verifyNeverAttached();
    }

    @Test
    void attach_relativeSerialPath_isBadRequest_andNeverWrites() {
        // The serial path must be an ABSOLUTE /dev/... device path (bean @Pattern -> 400).
        asAdmin().post().uri("/bff/admin/device-radios/dev-1/radios")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"transport\":\"serial\",\"serialPath\":\"ttyUSB0\","
                        + "\"radioId\":\"lora-0\",\"meshChannel\":0}")
                .exchange().expectStatus().isBadRequest();
        verifyNeverAttached();
    }

    @Test
    void attach_malformedGatewayNodeId_isBadRequest_andNeverWrites() {
        // gatewayNodeId must be a Meshtastic !hex8 node id (bean @Pattern -> 400).
        asAdmin().post().uri("/bff/admin/device-radios/dev-1/radios")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"transport\":\"mqtt\",\"host\":\"mqtt.example.org\",\"port\":1883,"
                        + "\"topicRoot\":\"msh/US\",\"channelName\":\"LongFast\","
                        + "\"gatewayNodeId\":\"0a1b2c3d\",\"radioId\":\"wan-0\",\"meshChannel\":0}")
                .exchange().expectStatus().isBadRequest();
        verifyNeverAttached();
    }

    @Test
    void attach_malformedRadioId_isBadRequest_andNeverWrites() {
        // radioId is the bridge-facing key: /^[A-Za-z0-9._-]{1,64}$/ (bean @Pattern -> 400).
        asAdmin().post().uri("/bff/admin/device-radios/dev-1/radios")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"transport\":\"serial\",\"serialPath\":\"/dev/ttyUSB0\","
                        + "\"radioId\":\"bad id!\",\"meshChannel\":0}")
                .exchange().expectStatus().isBadRequest();
        verifyNeverAttached();
    }

    // ── Signed per-node export — SUPERADMIN | internal-mTLS ONLY ─────────────────

    @Test
    void export_asSuperadmin_isAllowed() {
        var body = new RadioExportModels.RadioExportBody("fp-aaa", 3L, java.util.List.of());
        when(export.exportNode(eq("fp-aaa"))).thenReturn(Mono.just(
                new RadioExportModels.SignedRadioExport(body, "hash", "sig", "pub", true)));
        asSuperadmin().get().uri("/bff/admin/device-radios/export?node=fp-aaa")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.signed").isEqualTo(true)
                .jsonPath("$.body.nodeFp").isEqualTo("fp-aaa");
        verify(export).exportNode("fp-aaa");
    }

    @Test
    void export_asAdmin_isForbidden_andNeverReachesService() {
        // The export is the SAME SUPERADMIN | internal-mTLS gate as the device/storage
        // exports — an ADMIN JWT is 403 (a node never learns its radios via an ADMIN
        // principal).
        asAdmin().get().uri("/bff/admin/device-radios/export?node=fp-aaa")
                .exchange().expectStatus().isForbidden();
        verify(export, never()).exportNode(anyString());
    }

    @Test
    void export_asMod_isForbidden() {
        asMod().get().uri("/bff/admin/device-radios/export?node=fp-aaa")
                .exchange().expectStatus().isForbidden();
        verify(export, never()).exportNode(anyString());
    }

    @Test
    void export_withNoNode_isBadRequest_andNeverReachesService() {
        asSuperadmin().get().uri("/bff/admin/device-radios/export")
                .exchange().expectStatus().isBadRequest();
        verify(export, never()).exportNode(anyString());
    }
}
