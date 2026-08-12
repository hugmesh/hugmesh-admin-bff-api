package net.hugmesh.adminbff.phone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;

import java.time.Instant;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The phone-fleet SUPERADMIN role matrix — the acceptance bar for the SUPERADMIN-ONLY
 * boundary on {@code /bff/superadmin/phone-devices/**}. Mirrors
 * {@link net.hugmesh.adminbff.gamesservices.GamesCatalogSuperadminControllerTest}:
 * {@code @WebFluxTest} + the real {@link SecurityConfig} so BOTH the coarse
 * {@code /bff/superadmin/**} path gate AND the per-method
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} run.
 *
 * <ul>
 *   <li>SUPERADMIN — sees the whole fleet ({@code {"phones":[...]}}) + a single record;
 *       an unknown device id is a clean 404.</li>
 *   <li>ADMIN / USER — 403 on EVERY endpoint + never reach the service (an MDM phone
 *       record is superadmin/devops-plane inventory, not brand-admin data).</li>
 *   <li>UNAUTHENTICATED — 401 (unlike the ingest POST, which is the mTLS channel).</li>
 * </ul>
 */
@WebFluxTest(controllers = PhoneFleetSuperadminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class PhoneFleetSuperadminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean PhoneDeviceService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static PhoneDevice phone(String deviceId) {
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
                Instant.now(), Instant.now(), 1L,
                // changeset-304 operator state — a managed, locked phone so the fleet reads
                // surface every one of the seven new fields (a dropped mapping nulls them).
                "mesh_owned", "locked", "degraded", 3L, "reported stolen", "sa-actor",
                Instant.parse("2026-07-15T00:00:00Z"),
                // changeset-305 fleet-ownership columns — surface on the superadmin read too
                // (a dropped mapping would null them).
                "owner-sub", "acme.hugmesh.systems",
                // changeset-307 device-reported provider — surfaces on the superadmin read.
                "headwind", null);
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    void list_superadmin_seesFleetEnvelope() {
        when(service.list()).thenReturn(Flux.just(phone("phone-a"), phone("phone-b")));
        asSuperadmin().get().uri("/bff/superadmin/phone-devices")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.phones.length()").isEqualTo(2)
                .jsonPath("$.phones[0].deviceId").isEqualTo("phone-a")
                .jsonPath("$.phones[0].os").isEqualTo("GrapheneOS")
                // The v2 mdm facts surface through the read side with no mapping layer
                // of their own — a dropped domain component would null these.
                .jsonPath("$.phones[0].mdmEnrolled").isEqualTo(true)
                .jsonPath("$.phones[0].mdmDpcPackage").isEqualTo("com.hmdm.launcher")
                .jsonPath("$.phones[0].ingestCount").isEqualTo(1)
                // The seven changeset-304 management/lock fields surface on the fleet read.
                .jsonPath("$.phones[0].managementMode").isEqualTo("mesh_owned")
                .jsonPath("$.phones[0].lockState").isEqualTo("locked")
                .jsonPath("$.phones[0].lockPropagationState").isEqualTo("degraded")
                .jsonPath("$.phones[0].lockGeneration").isEqualTo(3)
                .jsonPath("$.phones[0].lockReason").isEqualTo("reported stolen")
                .jsonPath("$.phones[0].lockActor").isEqualTo("sa-actor")
                // The changeset-305 fleet-ownership columns surface on the superadmin read.
                .jsonPath("$.phones[0].physicalOwner").isEqualTo("owner-sub")
                .jsonPath("$.phones[0].ownerDomain").isEqualTo("acme.hugmesh.systems");
    }

    @Test
    void get_superadmin_singleRecord_and404OnUnknown() {
        when(service.find("phone-a")).thenReturn(Mono.just(phone("phone-a")));
        asSuperadmin().get().uri("/bff/superadmin/phone-devices/phone-a")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.deviceId").isEqualTo("phone-a")
                // The single-record read carries the management/lock fields too.
                .jsonPath("$.managementMode").isEqualTo("mesh_owned")
                .jsonPath("$.lockState").isEqualTo("locked")
                .jsonPath("$.lockGeneration").isEqualTo(3);

        when(service.find("phone-nope")).thenReturn(Mono.empty());
        asSuperadmin().get().uri("/bff/superadmin/phone-devices/phone-nope")
                .exchange().expectStatus().isNotFound();
    }

    @Test
    void list_admin_isForbidden_neverReachesService() {
        asAdmin().get().uri("/bff/superadmin/phone-devices")
                .exchange().expectStatus().isForbidden();
        asUser().get().uri("/bff/superadmin/phone-devices")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).list();
    }

    @Test
    void get_admin_isForbidden() {
        asAdmin().get().uri("/bff/superadmin/phone-devices/phone-a")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).find("phone-a");
    }

    @Test
    void unauthenticated_is401_unlikeTheIngestChannel() {
        web.get().uri("/bff/superadmin/phone-devices")
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).list();
    }

    /**
     * The 403s above are satisfiable by the COARSE /bff/superadmin/** path gate alone, so
     * they cannot detect a dropped per-method annotation. The defence-in-depth convention
     * (every superadmin method carries its own @PreAuthorize) is pinned structurally here.
     */
    @Test
    void everyEndpoint_carriesItsOwnPreAuthorize_defenceInDepth() throws Exception {
        for (var m : new java.lang.reflect.Method[]{
                PhoneFleetSuperadminController.class.getMethod("list"),
                PhoneFleetSuperadminController.class.getMethod("get", String.class)}) {
            var pa = m.getAnnotation(org.springframework.security.access.prepost.PreAuthorize.class);
            org.assertj.core.api.Assertions.assertThat(pa)
                    .as("%s must carry @PreAuthorize (defence-in-depth)", m.getName())
                    .isNotNull();
            org.assertj.core.api.Assertions.assertThat(pa.value())
                    .contains("hasRole('SUPERADMIN')");
        }
    }
}
