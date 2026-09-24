package net.hugmesh.adminbff.backingservices;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
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
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-layer contract for the managed backing-services endpoints. The SUPERADMIN-only gating,
 * the STEP-UP requirement on the mutating verb, the dark 503, the TIER-3 docs-only 409 refusal,
 * and the vocabulary 400 are the security-critical surface; the deeper mechanism (persist +
 * outbox in one tx) is covered in {@link BackingServiceModeRepositoryTest} /
 * {@link BackingServiceOutboxTransactionTest}. The service + step-up gate are mocked so the
 * controller's gates are isolated; {@code verify(service, never())} backs each deny (the
 * controller REFUSES before ever calling the service). Direct clone of
 * {@code GoLiveControllerTest}.
 */
@WebFluxTest(controllers = BackingServiceController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class BackingServiceControllerTest {

    private static final String STEP_UP = BackingServiceStepUpGate.STEP_UP_HEADER;
    private static final String TOKEN = "good-token";
    private static final String MANAGED_BODY = """
            {"mode":"managed","endpoint":"my-db.rds.amazonaws.com:5432","credsRef":"hugmesh/postgres-admin-bff"}""";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean BackingServiceService service;
    @MockitoBean BackingServiceStepUpGate stepUp;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void mfaDarkByDefault() {
        // A5 MFA leg ships DARK: no fresh stamp, nothing to consume — only the workload step-up
        // token leg satisfies. The 3-arg unified gate delegates to the 2-arg token leg tests stub.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static BackingServiceMode managed() {
        return new BackingServiceMode("bsm-1", "postgres-admin-bff", "managed",
                "my-db.rds.amazonaws.com:5432", "hugmesh/postgres-admin-bff",
                "superadmin@infra", Instant.now(), 1L);
    }

    // ── catalog + state: SUPERADMIN-only (cross-domain infra, above a brand admin) ──
    @Test
    void catalog_superadmin_carriesEnabledFlagAndState() {
        when(service.isEnabled()).thenReturn(false);
        when(service.catalogWithState()).thenReturn(Mono.just(List.of(
                Map.of("id", "velero-objectstore", "kind", "object-storage", "tier", 1,
                        "docsOnly", false, "currentMode", "self-hosted"),
                Map.of("id", "vault-pki", "kind", "pki", "tier", 3,
                        "docsOnly", true, "currentMode", "self-hosted"))));
        asSuperadmin().get().uri("/bff/superadmin/backing-services")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.enabled").isEqualTo(false)
                .jsonPath("$.services[0].id").isEqualTo("velero-objectstore")
                .jsonPath("$.services[0].currentMode").isEqualTo("self-hosted")
                .jsonPath("$.services[1].docsOnly").isEqualTo(true)
                .jsonPath("$.note").value(org.hamcrest.Matchers.containsString("byte-identical default"));
    }

    @Test
    void catalog_admin_403_belowTheSuperadminWall() {
        asAdmin().get().uri("/bff/superadmin/backing-services").exchange().expectStatus().isForbidden();
    }

    @Test
    void catalog_user_403_and_unauthenticated_401() {
        asUser().get().uri("/bff/superadmin/backing-services").exchange().expectStatus().isForbidden();
        web.get().uri("/bff/superadmin/backing-services").exchange().expectStatus().isUnauthorized();
    }

    // ── set mode: role + step-up gates ───────────────────────────────────────────────
    @Test
    void setMode_admin_403_noServiceCall() {
        asAdmin().put().uri("/bff/superadmin/backing-services/postgres-admin-bff/mode")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(MANAGED_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(service, never()).recordMode(any(), any(), any());
    }

    @Test
    void setMode_unauthenticated_401() {
        web.put().uri("/bff/superadmin/backing-services/postgres-admin-bff/mode")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(MANAGED_BODY)
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).recordMode(any(), any(), any());
    }

    @Test
    void setMode_missingStepUp_403_noServiceCall() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().put().uri("/bff/superadmin/backing-services/postgres-admin-bff/mode")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(MANAGED_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).recordMode(any(), any(), any());
    }

    @Test
    void setMode_invalidStepUp_403() {
        when(stepUp.isSatisfied(any(), eq("bad"))).thenReturn(false);
        asSuperadmin().put().uri("/bff/superadmin/backing-services/postgres-admin-bff/mode")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(MANAGED_BODY)
                .header(STEP_UP, "bad").exchange().expectStatus().isForbidden();
        verify(service, never()).recordMode(any(), any(), any());
    }

    @Test
    void setMode_blankMode_400_noServiceCall() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        asSuperadmin().put().uri("/bff/superadmin/backing-services/postgres-admin-bff/mode")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"mode\":\"\"}")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isBadRequest();
        verify(service, never()).recordMode(any(), any(), any());
    }

    @Test
    void setMode_withStepUp_returnsRecordedIntent() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.recordMode(any(), eq("postgres-admin-bff"), any())).thenReturn(Mono.just(managed()));
        asSuperadmin().put().uri("/bff/superadmin/backing-services/postgres-admin-bff/mode")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(MANAGED_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("bsm-1")
                .jsonPath("$.serviceId").isEqualTo("postgres-admin-bff")
                .jsonPath("$.mode").isEqualTo("managed")
                .jsonPath("$.note").value(org.hamcrest.Matchers.containsString("intent recorded only"));
    }

    // ── ships dark -> 503 dark descriptor ────────────────────────────────────────────
    @Test
    void setMode_dark_503_descriptor() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.recordMode(any(), any(), any()))
                .thenReturn(Mono.error(new BackingServiceService.BackingServiceDarkException()));
        asSuperadmin().put().uri("/bff/superadmin/backing-services/postgres-admin-bff/mode")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(MANAGED_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.dark").isEqualTo(true);
    }

    // ── tier-3 docs-only refusal -> 409 ──────────────────────────────────────────────
    @Test
    void setMode_tier3DocsOnly_409() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.recordMode(any(), eq("vault-pki"), any()))
                .thenReturn(Mono.error(new BackingServiceService.BackingServiceDocsOnlyException("vault-pki")));
        asSuperadmin().put().uri("/bff/superadmin/backing-services/vault-pki/mode")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(MANAGED_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isEqualTo(409)
                .expectBody().jsonPath("$.error").value(org.hamcrest.Matchers.containsString("DOCS-ONLY"));
    }

    // ── vocabulary refusal -> 400 ────────────────────────────────────────────────────
    @Test
    void setMode_vocabularyRefusal_400() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.recordMode(any(), any(), any()))
                .thenReturn(Mono.error(new BackingServiceService.BackingServiceValidationException(
                        "a managed mode requires an endpoint")));
        asSuperadmin().put().uri("/bff/superadmin/backing-services/postgres-admin-bff/mode")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(MANAGED_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isBadRequest();
    }
}
