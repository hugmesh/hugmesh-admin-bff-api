package net.hugmesh.adminbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.device.DeviceLicenseController;
import net.hugmesh.adminbff.device.DeviceLicenseInternalExportController;
import net.hugmesh.adminbff.device.DevicePendingService;
import net.hugmesh.adminbff.device.DeviceRegistryExportService;
import net.hugmesh.adminbff.device.DeviceRegistryService;
import net.hugmesh.adminbff.device.ExportModels;
import net.hugmesh.adminbff.device.SshLicenseService;
import net.hugmesh.adminbff.domainregistry.DomainExportModels;
import net.hugmesh.adminbff.domainregistry.DomainRegistryController;
import net.hugmesh.adminbff.domainregistry.DomainRegistryExportService;
import net.hugmesh.adminbff.domainregistry.DomainRegistryInternalController;
import net.hugmesh.adminbff.domainregistry.DomainRegistryService;
import net.hugmesh.adminbff.egressvpn.EgressVpnController;
import net.hugmesh.adminbff.egressvpn.EgressVpnInternalExportController;
import net.hugmesh.adminbff.egressvpn.EgressVpnService;
import net.hugmesh.adminbff.egressvpn.VpnExportModels;
import net.hugmesh.adminbff.egressvpn.VpnExportService;
import net.hugmesh.adminbff.golive.GoLiveController;
import net.hugmesh.adminbff.golive.GoLiveExportModels;
import net.hugmesh.adminbff.golive.GoLiveExportService;
import net.hugmesh.adminbff.golive.GoLiveInternalExportController;
import net.hugmesh.adminbff.golive.GoLiveService;
import net.hugmesh.adminbff.golive.GoLiveStepUpGate;
import net.hugmesh.adminbff.radio.NodeRadioExportService;
import net.hugmesh.adminbff.radio.NodeRadioService;
import net.hugmesh.adminbff.radio.RadioDeviceController;
import net.hugmesh.adminbff.radio.RadioDeviceInternalExportController;
import net.hugmesh.adminbff.radio.RadioExportModels;
import net.hugmesh.adminbff.storage.NodeStorageExportService;
import net.hugmesh.adminbff.storage.NodeStorageService;
import net.hugmesh.adminbff.storage.StorageExportModels;
import net.hugmesh.adminbff.storage.StoragePoolController;
import net.hugmesh.adminbff.storage.StoragePoolInternalExportController;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * DECISION 89b = A (2026-09-23, hugmesh-admin-bff-api#6): node agents hold the shared
 * {@code X-Internal-Token}, which grants {@code ROLE_SERVICE} on {@code /bff/internal/**} only, so
 * each of the six SUPERADMIN-only signed exports gets an INTERNAL MIRROR. This pins, for every one:
 *
 * <ul>
 *   <li>the mirror EXISTS at {@code /bff/internal/<same-segment>/export} (404 on origin/main
 *       d5b065c, where no such route existed);</li>
 *   <li>with a valid token it returns the SAME BYTES as its SUPERADMIN twin for the same query —
 *       the export services are stubbed to derive their whole output from their arguments, so a
 *       mirror that dropped, swapped or re-spelled a parameter produces different bytes;</li>
 *   <li>it REFUSES without the token (401), with a wrong token (401), and to a SUPERADMIN JWT
 *       (403 — the hierarchy has no SUPERADMIN-to-SERVICE edge, which is the point of the gate);</li>
 *   <li>the token does NOT open the SUPERADMIN twin (401), so a shared node secret never becomes
 *       an admin bypass;</li>
 *   <li>the parameter refusals match the twin's (400 for the same missing parameter).</li>
 * </ul>
 *
 * <p>The token is ARMED ({@code app.internal.token} set), the production state, and auth-core's
 * {@code InternalTokenWebFilter} is excluded exactly as {@code InternalSurfaceRoleMatrixTest}
 * does, so every status here is a statement about the route policy itself.
 */
@WebFluxTest(controllers = {
        DomainRegistryController.class, DomainRegistryInternalController.class,
        DeviceLicenseController.class, DeviceLicenseInternalExportController.class,
        EgressVpnController.class, EgressVpnInternalExportController.class,
        GoLiveController.class, GoLiveInternalExportController.class,
        RadioDeviceController.class, RadioDeviceInternalExportController.class,
        StoragePoolController.class, StoragePoolInternalExportController.class},
        excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE,
                classes = net.hugmesh.authcore.config.InternalTokenWebFilter.class))
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
@TestPropertySource(properties = {
        "app.internal.token=s3cret",
        "app.internal.token-header=X-Internal-Token"
})
class NodeExportInternalMirrorTest {

    static final String TOKEN = "s3cret";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    // domain registry
    @MockitoBean DomainRegistryService domainService;
    @MockitoBean DomainRegistryExportService domainExport;
    // device licenses
    @MockitoBean DeviceRegistryService devices;
    @MockitoBean SshLicenseService licenses;
    @MockitoBean DeviceRegistryExportService deviceExport;
    @MockitoBean DevicePendingService pending;
    // egress vpn
    @MockitoBean EgressVpnService vpn;
    @MockitoBean VpnExportService vpnExport;
    // go-live
    @MockitoBean GoLiveService goLive;
    @MockitoBean GoLiveExportService goLiveExport;
    @MockitoBean GoLiveStepUpGate stepUp;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    // radios
    @MockitoBean NodeRadioService radios;
    @MockitoBean NodeRadioExportService radioExport;
    // storage pools
    @MockitoBean NodeStorageService storage;
    @MockitoBean NodeStorageExportService storageExport;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
        // Every stub derives its ENTIRE output from its arguments (and which method was called),
        // so two routes return equal bytes only if they called the same method with the same
        // values. A constant stub would make the byte comparison vacuous.
        when(domainExport.exportRegistry(nullable(String.class))).thenAnswer(inv -> Mono.just(
                new DomainExportModels.SignedDomainExport(
                        new DomainExportModels.DomainExportBody(String.valueOf((Object) inv.getArgument(0)),
                                7L, List.of()),
                        "hash-dom-" + inv.getArgument(0), "sig-dom-" + inv.getArgument(0),
                        "pub", true)));
        when(deviceExport.exportNode(anyString())).thenAnswer(inv -> Mono.just(
                deviceExport("node:" + inv.getArgument(0))));
        when(deviceExport.exportMesh(anyString())).thenAnswer(inv -> Mono.just(
                deviceExport("mesh:" + inv.getArgument(0))));
        when(vpnExport.exportNode(anyString())).thenAnswer(inv -> Mono.just(
                new VpnExportModels.SignedVpnExport(
                        new VpnExportModels.VpnExportBody(inv.getArgument(0), 3L, List.of()),
                        "hash-vpn-" + inv.getArgument(0), "sig-vpn-" + inv.getArgument(0),
                        "pub", true)));
        when(goLiveExport.exportIntents(nullable(String.class))).thenAnswer(inv -> Mono.just(
                new GoLiveExportModels.SignedGoLiveExport(
                        new GoLiveExportModels.GoLiveExportBody(String.valueOf((Object) inv.getArgument(0)),
                                5L, List.of()),
                        "hash-gl-" + inv.getArgument(0), "sig-gl-" + inv.getArgument(0),
                        "pub", true)));
        when(radioExport.exportNode(anyString())).thenAnswer(inv -> Mono.just(
                new RadioExportModels.SignedRadioExport(
                        new RadioExportModels.RadioExportBody(inv.getArgument(0), 11L, List.of()),
                        "hash-radio-" + inv.getArgument(0), "sig-radio-" + inv.getArgument(0),
                        "pub", true)));
        when(storageExport.exportNode(anyString())).thenAnswer(inv -> Mono.just(
                new StorageExportModels.SignedStorageExport(
                        new StorageExportModels.StorageExportBody(inv.getArgument(0), 13L, List.of()),
                        "hash-st-" + inv.getArgument(0), "sig-st-" + inv.getArgument(0),
                        "pub", true)));
    }

    private static ExportModels.SignedExport deviceExport(String key) {
        return new ExportModels.SignedExport(new ExportModels.ExportBody(key, 9L, List.of()),
                "hash-dev-" + key, "sig-dev-" + key, "pub", true);
    }

    /**
     * {@code (admin twin, internal mirror)} pairs, one per export and per query shape the twin
     * accepts. The internal path is the admin path with {@code /bff/admin/} replaced by
     * {@code /bff/internal/} — stated literally here so a renamed route fails loudly.
     */
    static Stream<String[]> pairs() {
        return Stream.of(
                new String[]{"/bff/admin/domains/export", "/bff/internal/domains/export"},
                new String[]{"/bff/admin/domains/export?node=fp-1", "/bff/internal/domains/export?node=fp-1"},
                new String[]{"/bff/admin/device-licenses/export?node=fp-1",
                        "/bff/internal/device-licenses/export?node=fp-1"},
                new String[]{"/bff/admin/device-licenses/export?mesh=m-1",
                        "/bff/internal/device-licenses/export?mesh=m-1"},
                new String[]{"/bff/admin/device-licenses/export?node=fp-1&mesh=m-1",
                        "/bff/internal/device-licenses/export?node=fp-1&mesh=m-1"},
                new String[]{"/bff/admin/egress-vpn/export?node=fp-1",
                        "/bff/internal/egress-vpn/export?node=fp-1"},
                new String[]{"/bff/admin/go-live/export", "/bff/internal/go-live/export"},
                new String[]{"/bff/admin/go-live/export?node=fp-1", "/bff/internal/go-live/export?node=fp-1"},
                new String[]{"/bff/admin/device-radios/export?node=fp-1",
                        "/bff/internal/device-radios/export?node=fp-1"},
                new String[]{"/bff/admin/device-storage-pools/export?node=fp-1",
                        "/bff/internal/device-storage-pools/export?node=fp-1"});
    }

    /** One internal path per export — the six the decision names. */
    static Stream<String> internalPaths() {
        return Stream.of(
                "/bff/internal/domains/export?node=fp-1",
                "/bff/internal/device-licenses/export?node=fp-1",
                "/bff/internal/egress-vpn/export?node=fp-1",
                "/bff/internal/go-live/export?node=fp-1",
                "/bff/internal/device-radios/export?node=fp-1",
                "/bff/internal/device-storage-pools/export?node=fp-1");
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private byte[] body(WebTestClient.RequestHeadersSpec<?> spec) {
        byte[] bytes = spec.exchange().expectStatus().isOk()
                .expectBody().returnResult().getResponseBody();
        assertThat(bytes).as("a signed export body").isNotNull().isNotEmpty();
        return bytes;
    }

    @ParameterizedTest(name = "{1} returns the same signed bytes as {0}")
    @MethodSource("pairs")
    void mirror_withToken_returnsTheTwinsBytes(String adminPath, String internalPath) {
        byte[] twin = body(asSuperadmin().get().uri(adminPath));
        byte[] mirror = body(web.get().uri(internalPath).header("X-Internal-Token", TOKEN));
        assertThat(new String(mirror, StandardCharsets.UTF_8))
                .isEqualTo(new String(twin, StandardCharsets.UTF_8));
        assertThat(mirror).isEqualTo(twin);
    }

    @ParameterizedTest(name = "{0} — no token is 401")
    @MethodSource("internalPaths")
    void mirror_withoutToken_is401(String internalPath) {
        web.get().uri(internalPath).exchange().expectStatus().isUnauthorized();
    }

    @ParameterizedTest(name = "{0} — wrong token is 401")
    @MethodSource("internalPaths")
    void mirror_withWrongToken_is401(String internalPath) {
        web.get().uri(internalPath).header("X-Internal-Token", "WRONG")
                .exchange().expectStatus().isUnauthorized();
    }

    @ParameterizedTest(name = "{0} — a SUPERADMIN JWT is 403")
    @MethodSource("internalPaths")
    void mirror_refusesAHumanSuperadmin(String internalPath) {
        asSuperadmin().get().uri(internalPath).exchange().expectStatus().isForbidden();
    }

    @ParameterizedTest(name = "{0} — the token does not open the SUPERADMIN twin")
    @MethodSource("internalPaths")
    void token_doesNotOpenTheAdminTwin(String internalPath) {
        String adminPath = internalPath.replace("/bff/internal/", "/bff/admin/");
        web.get().uri(adminPath).header("X-Internal-Token", TOKEN)
                .exchange().expectStatus().isUnauthorized();
    }

    @ParameterizedTest(name = "{0} — the same missing-parameter 400 as the twin")
    @ValueSource(strings = {
            "/bff/internal/device-licenses/export",
            "/bff/internal/egress-vpn/export",
            "/bff/internal/device-radios/export",
            "/bff/internal/device-storage-pools/export"})
    void mirror_refusesAMissingNodeLikeItsTwin(String internalPath) {
        String adminPath = internalPath.replace("/bff/internal/", "/bff/admin/");
        asSuperadmin().get().uri(adminPath).exchange().expectStatus().isBadRequest();
        web.get().uri(internalPath).header("X-Internal-Token", TOKEN)
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void mirror_carriesNoPreAuthorize() {
        // A copied @PreAuthorize("hasRole('SUPERADMIN')") would 403 the token holder: the internal
        // mirrors are reachable ONLY because they do not carry one. Checked by reflection too, so
        // the reason a mutation fails is named rather than inferred from a status code.
        for (Class<?> c : List.of(DomainRegistryInternalController.class,
                DeviceLicenseInternalExportController.class, EgressVpnInternalExportController.class,
                GoLiveInternalExportController.class, RadioDeviceInternalExportController.class,
                StoragePoolInternalExportController.class)) {
            assertThat(c.isAnnotationPresent(
                    org.springframework.security.access.prepost.PreAuthorize.class)).as(c.getName()).isFalse();
            for (var m : c.getDeclaredMethods()) {
                assertThat(m.isAnnotationPresent(
                        org.springframework.security.access.prepost.PreAuthorize.class))
                        .as(c.getSimpleName() + "#" + m.getName()).isFalse();
            }
        }
    }
}
