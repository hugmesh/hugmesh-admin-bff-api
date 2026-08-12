package net.hugmesh.adminbff.device;
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
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The node LIVENESS self-report acceptance bar — proves the channel is mTLS-shaped (NO JWT) and
 * carries NO AUTHORIZING DATA.
 *
 * <ul>
 *   <li><b>NO CASDOOR JWT REQUIRED: a request with no Casdoor token is accepted</b> — the node
 *       authenticates with the in-cluster {@code X-Internal-Token} instead, which
 *       {@code SecurityConfig} promotes to the {@code ROLE_SERVICE} principal
 *       {@code /bff/internal/**} requires (UNARMED here — no {@code app.internal.token} is
 *       configured in this slice, the dev/test parity branch), unlike {@code /bff/admin/**}
 *       which would 401/403 without a role. The armed role matrix is
 *       {@code InternalSurfaceRoleMatrixTest}.</li>
 *   <li>NO AUTHORIZING COLUMNS: the request body has no owner/domain/license/role fields, and
 *       the service is called with ONLY the fingerprint + reconciliation hints — there is no
 *       path by which a self-report confers access.</li>
 *   <li>The ACK is minimal (accepted + the node's own report count); it leaks nothing about
 *       the registry/licenses.</li>
 *   <li>A malformed body (blank fp) is a clean 400 and NEVER writes.</li>
 * </ul>
 */
@WebFluxTest(controllers = DeviceEnrollmentController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class DeviceEnrollmentSelfReportTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean DeviceEnrollmentService enrollment;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static DeviceEnrollment row(String fp, long count) {
        return new DeviceEnrollment("e-1", fp, "node-1", "mesh-1", "tn-1",
                Instant.now(), Instant.now(), count);
    }

    private static final String BODY =
            "{\"machineKeyFp\":\"nodekey:SELF\",\"hostname\":\"node-1\",\"meshId\":\"mesh-1\",\"tailnetId\":\"tn-1\"}";

    @Test
    void selfReport_noJwt_isAccepted_mtlsTransportGate() {
        when(enrollment.record(eq("nodekey:SELF"), eq("node-1"), eq("mesh-1"), eq("tn-1")))
                .thenReturn(Mono.just(row("nodekey:SELF", 1L)));
        // NO .mutateWith(mockJwt()) — no Casdoor token, exactly as the node presents (mTLS +
        // X-Internal-Token). /bff/internal/** is ROLE_SERVICE; this slice configures no
        // app.internal.token, the UNARMED dev/test parity branch (see InternalSurfaceRoleMatrixTest).
        web.post().uri("/bff/internal/device-enrollment/self-report")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.accepted").isEqualTo(true)
                .jsonPath("$.reportCount").isEqualTo(1);
        // Called with ONLY the fp + reconciliation hints — no authorizing arguments exist.
        verify(enrollment).record(eq("nodekey:SELF"), eq("node-1"), eq("mesh-1"), eq("tn-1"));
    }

    @Test
    void selfReport_reReport_bumpsCount() {
        when(enrollment.record(eq("nodekey:SELF"), eq("node-1"), eq("mesh-1"), eq("tn-1")))
                .thenReturn(Mono.just(row("nodekey:SELF", 7L)));
        web.post().uri("/bff/internal/device-enrollment/self-report")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.reportCount").isEqualTo(7);
    }

    @Test
    void selfReport_minimalBody_onlyFp_isAccepted() {
        when(enrollment.record(eq("nodekey:BARE"), isNull(), isNull(), isNull()))
                .thenReturn(Mono.just(row("nodekey:BARE", 1L)));
        web.post().uri("/bff/internal/device-enrollment/self-report")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"machineKeyFp\":\"nodekey:BARE\"}")
                .exchange().expectStatus().isOk();
        verify(enrollment).record(eq("nodekey:BARE"), isNull(), isNull(), isNull());
    }

    @Test
    void selfReport_blankFp_isBadRequest_andNeverWrites() {
        web.post().uri("/bff/internal/device-enrollment/self-report")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"machineKeyFp\":\"\"}")
                .exchange().expectStatus().isBadRequest();
        verify(enrollment, never()).record(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    void selfReport_evenWithAnAdminJwt_stillJustReconciles_noPrivilegedEffect() {
        // Defence-in-depth note: even if a JWT happens to be present, the endpoint only ever
        // upserts reconciliation telemetry — there is no authorizing field to set.
        when(enrollment.record(eq("nodekey:SELF"), eq("node-1"), eq("mesh-1"), eq("tn-1")))
                .thenReturn(Mono.just(row("nodekey:SELF", 1L)));
        web.mutateWith(org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers
                        .mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .post().uri("/bff/internal/device-enrollment/self-report")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(BODY)
                .exchange().expectStatus().isOk();
        verify(enrollment).record(eq("nodekey:SELF"), eq("node-1"), eq("mesh-1"), eq("tn-1"));
    }
}
