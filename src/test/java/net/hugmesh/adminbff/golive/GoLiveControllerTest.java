package net.hugmesh.adminbff.golive;

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
import net.hugmesh.adminbff.golive.GoLiveExportModels.GoLiveExportBody;
import net.hugmesh.adminbff.golive.GoLiveExportModels.SignedGoLiveExport;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;

import java.time.Instant;
import java.util.List;

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
 * Web-layer contract for the go-live wizard endpoints. The SUPERADMIN-only gating, the STEP-UP
 * requirement on the mutating verbs, the dark 503, and the INTENT-ONLY honesty contract
 * ({@code applied:false} + hostAgent note on record — this backend NEVER claims it flipped the
 * host marker) are the security-critical surface; the deeper mechanism is covered in
 * {@link GoLiveServiceTest} / {@link GoLiveExportServiceTest}. The service + step-up gate are
 * mocked so the controller's gates are isolated; {@code verify(service, never())} backs each
 * deny (the controller REFUSES before ever calling the service).
 */
@WebFluxTest(controllers = GoLiveController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class GoLiveControllerTest {

    private static final String STEP_UP = GoLiveStepUpGate.STEP_UP_HEADER;
    private static final String TOKEN = "good-token";
    private static final String GO_PUBLIC_BODY = """
            {"clusterDomain":"acme.example","targetState":"public",
             "exposureModel":"tunnel","provider":"cloudflare-tunnel"}""";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean GoLiveService service;
    @MockitoBean GoLiveExportService export;
    @MockitoBean GoLiveStepUpGate stepUp;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void mfaDarkByDefault() {
        // A5 MFA leg ships DARK: no fresh stamp, nothing to consume — only the workload
        // step-up token leg satisfies (today's behaviour). The 3-arg unified gate delegates
        // to the 2-arg token leg the individual tests stub.
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

    private static GoLiveIntent recorded() {
        return new GoLiveIntent("gl-1", "acme.example", "public", "tunnel", "cloudflare-tunnel",
                GoLiveIntent.STATUS_RECORDED, null, "superadmin@infra",
                Instant.now(), Instant.now(), 1L, null, null);
    }

    // ── status: SUPERADMIN-only (cross-domain infra, above a brand admin) ───────────
    @Test
    void status_superadmin_carriesEnabledFlagAndHostAgentNote() {
        when(service.isEnabled()).thenReturn(false);
        when(service.history()).thenReturn(Flux.just(recorded()));
        asSuperadmin().get().uri("/bff/admin/go-live")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.enabled").isEqualTo(false)
                .jsonPath("$.intents[0].id").isEqualTo("gl-1")
                .jsonPath("$.intents[0].applied").isEqualTo(false)
                .jsonPath("$.hostAgent").value(org.hamcrest.Matchers.containsString(
                        "never flips the marker"));
    }

    @Test
    void status_admin_403_belowTheSuperadminWall() {
        asAdmin().get().uri("/bff/admin/go-live").exchange().expectStatus().isForbidden();
    }

    @Test
    void status_user_403_and_unauthenticated_401() {
        asUser().get().uri("/bff/admin/go-live").exchange().expectStatus().isForbidden();
        web.get().uri("/bff/admin/go-live").exchange().expectStatus().isUnauthorized();
    }

    // ── providers: the static catalog ────────────────────────────────────────────────
    @Test
    void providers_superadmin_rendersTheCatalog() {
        when(service.providers()).thenReturn(GoLiveProviderCatalog.PROVIDERS);
        asSuperadmin().get().uri("/bff/admin/go-live/providers")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.providers[0].key").isEqualTo("cloudflare-tunnel")
                .jsonPath("$.exposureModels[0]").isEqualTo("tunnel");
    }

    @Test
    void providers_admin_403() {
        asAdmin().get().uri("/bff/admin/go-live/providers").exchange().expectStatus().isForbidden();
    }

    // ── record: role + step-up gates ─────────────────────────────────────────────────
    @Test
    void record_admin_403_noServiceCall() {
        asAdmin().post().uri("/bff/admin/go-live/intents")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GO_PUBLIC_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(service, never()).record(any(), any());
    }

    @Test
    void record_unauthenticated_401() {
        web.post().uri("/bff/admin/go-live/intents")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GO_PUBLIC_BODY)
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).record(any(), any());
    }

    @Test
    void record_missingStepUp_403_noServiceCall() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().post().uri("/bff/admin/go-live/intents")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GO_PUBLIC_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).record(any(), any());
    }

    @Test
    void record_invalidStepUp_403() {
        when(stepUp.isSatisfied(any(), eq("bad"))).thenReturn(false);
        asSuperadmin().post().uri("/bff/admin/go-live/intents")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GO_PUBLIC_BODY)
                .header(STEP_UP, "bad").exchange().expectStatus().isForbidden();
        verify(service, never()).record(any(), any());
    }

    @Test
    void record_blankBody_400_noServiceCall() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        asSuperadmin().post().uri("/bff/admin/go-live/intents")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"clusterDomain\":\"\",\"targetState\":\"\"}")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isBadRequest();
        verify(service, never()).record(any(), any());
    }

    @Test
    void record_withStepUp_returnsRecordedIntent_neverClaimsApplied() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.record(any(), any())).thenReturn(Mono.just(recorded()));
        asSuperadmin().post().uri("/bff/admin/go-live/intents")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GO_PUBLIC_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("gl-1")
                .jsonPath("$.status").isEqualTo("recorded")
                // THE CONTRACT, on the wire: recording never flips the host marker.
                .jsonPath("$.applied").isEqualTo(false)
                .jsonPath("$.hostAgent").value(org.hamcrest.Matchers.containsString(
                        "/etc/hugmesh/go-live"));
    }

    /**
     * The MFA leg reads the session the principal came from: an explicit {@code Bearer bff_A}
     * wins over a {@code bff_session} cookie of another session, so B's fresh stamp is neither
     * counted for A nor consumed.
     */
    @Test
    void record_bearerSessionWithoutMfa_plusAnotherSessionsFreshCookie_isRefused_andBsStampUntouched() {
        when(mfaStepUp.isFresh("bff_A")).thenReturn(Mono.just(false));
        when(mfaStepUp.isFresh("bff_B")).thenReturn(Mono.just(true));
        when(service.record(any(), any())).thenReturn(Mono.just(recorded()));
        asSuperadmin().mutateWith(org.springframework.security.test.web.reactive.server
                        .SecurityMockServerConfigurers.csrf())
                .post().uri("/bff/admin/go-live/intents")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GO_PUBLIC_BODY)
                .header(org.springframework.http.HttpHeaders.AUTHORIZATION, "Bearer bff_A")
                .cookie("bff_session", "bff_B")
                .exchange().expectStatus().is4xxClientError();
        verify(mfaStepUp).isFresh("bff_A");
        verify(mfaStepUp, never()).isFresh("bff_B");
        verify(mfaStepUp, never()).consume("bff_B");
        verify(service, never()).record(any(), any());
    }

    // ── ships dark -> 503 dark descriptor ────────────────────────────────────────────
    @Test
    void record_dark_503_descriptor() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.record(any(), any()))
                .thenReturn(Mono.error(new GoLiveService.GoLiveDarkException()));
        asSuperadmin().post().uri("/bff/admin/go-live/intents")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GO_PUBLIC_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.dark").isEqualTo(true);
    }

    // ── vocabulary refusal -> 400 ────────────────────────────────────────────────────
    @Test
    void record_vocabularyRefusal_400() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.record(any(), any()))
                .thenReturn(Mono.error(new GoLiveService.GoLiveValidationException("bad vocab")));
        asSuperadmin().post().uri("/bff/admin/go-live/intents")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(GO_PUBLIC_BODY)
                .header(STEP_UP, TOKEN).exchange().expectStatus().isBadRequest();
    }

    // ── withdraw: role + step-up gates ───────────────────────────────────────────────
    @Test
    void withdraw_admin_403_noServiceCall() {
        asAdmin().delete().uri("/bff/admin/go-live/intents/gl-1")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(service, never()).withdraw(any(), any());
    }

    @Test
    void withdraw_missingStepUp_403_noServiceCall() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().delete().uri("/bff/admin/go-live/intents/gl-1")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).withdraw(any(), any());
    }

    @Test
    void withdraw_withStepUp_reportsCasOutcome() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.withdraw(any(), eq("gl-1"))).thenReturn(Mono.just(1L));
        asSuperadmin().delete().uri("/bff/admin/go-live/intents/gl-1")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.withdrawn").isEqualTo(true)
                .jsonPath("$.id").isEqualTo("gl-1");
    }

    @Test
    void withdraw_dark_503() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.withdraw(any(), eq("gl-1")))
                .thenReturn(Mono.error(new GoLiveService.GoLiveDarkException()));
        asSuperadmin().delete().uri("/bff/admin/go-live/intents/gl-1")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.dark").isEqualTo(true);
    }

    // ── export: the host agent's signed channel (SUPERADMIN | internal mTLS) ─────────
    @Test
    void export_superadmin_servesTheSignedEnvelope() {
        when(export.exportIntents(any())).thenReturn(Mono.just(new SignedGoLiveExport(
                new GoLiveExportBody("fp-node", 3L, List.of()),
                "hash", "sig", "pub", true)));
        asSuperadmin().get().uri("/bff/admin/go-live/export?node=fp-node")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.signed").isEqualTo(true)
                .jsonPath("$.body.node").isEqualTo("fp-node")
                .jsonPath("$.body.generation").isEqualTo(3);
    }

    @Test
    void export_admin_403_and_user_403() {
        asAdmin().get().uri("/bff/admin/go-live/export").exchange().expectStatus().isForbidden();
        asUser().get().uri("/bff/admin/go-live/export").exchange().expectStatus().isForbidden();
    }
}
