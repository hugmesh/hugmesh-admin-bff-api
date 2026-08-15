package net.hugmesh.adminbff.sshissue;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.StepUpRequiredException;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.nio.charset.StandardCharsets;

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
 * Web-layer contract for the admin SSH key-ISSUANCE endpoints. The SUPERADMIN-only gating, the
 * STEP-UP requirement, the dark 503, and the single-use 410 are the security-critical surface;
 * the deeper mechanism is covered in {@link AdminSshKeyIssuanceServiceTest}. The service +
 * step-up gate are mocked here so the controller's gates are isolated.
 *
 * <p>The whole point of mocking is to prove the controller REFUSES (403/401/503) BEFORE ever
 * calling the service — so {@code verify(service, never())} backs each deny.
 */
@WebFluxTest(controllers = AdminSshKeyIssuanceController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class AdminSshKeyIssuanceControllerTest {

    private static final String STEP_UP = SshKeyIssueStepUpGate.STEP_UP_HEADER;
    private static final String TOKEN = "good-token";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean AdminSshKeyIssuanceService service;
    @MockitoBean SshKeyIssueStepUpGate stepUp;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void mfaDarkByDefault() {
        // A5 MFA leg ships DARK: no fresh stamp, nothing to consume — so only the workload
        // step-up token leg satisfies (today's behaviour). The 3-arg unified gate then delegates
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

    // ── issue: role + step-up gates ─────────────────────────────────────────────────
    @Test
    void issue_nonSuperadmin_403_noServiceCall() {
        // ADMIN is below the SUPERADMIN floor on the mutating verb.
        asAdmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-1")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(service, never()).issue(any(), any(), any());
    }

    @Test
    void issue_user_403() {
        asUser().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-1")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(service, never()).issue(any(), any(), any());
    }

    @Test
    void issue_unauthenticated_401() {
        web.post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-1")
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).issue(any(), any(), any());
    }

    @Test
    void issue_missingStepUp_403_noServiceCall() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-1")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).issue(any(), any(), any());
    }

    @Test
    void issue_invalidStepUp_403() {
        when(stepUp.isSatisfied(any(), eq("bad"))).thenReturn(false);
        asSuperadmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-1")
                .header(STEP_UP, "bad").exchange().expectStatus().isForbidden();
        verify(service, never()).issue(any(), any(), any());
    }

    @Test
    void issue_missingDeviceId_400() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(true);
        asSuperadmin().post().uri("/bff/admin/ssh-issue/issue")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isBadRequest();
        verify(service, never()).issue(any(), any(), any());
    }

    @Test
    void issue_withStepUp_returnsResult() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.issue(any(), eq("dev-1"), any())).thenReturn(Mono.just(
                new AdminSshKeyIssuanceService.IssueResult("ik-1", "SHA256:zzz",
                        "ssh-ed25519 AAAA", null, true)));
        asSuperadmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-1")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.issuedKeyId").isEqualTo("ik-1")
                .jsonPath("$.fingerprint").isEqualTo("SHA256:zzz")
                .jsonPath("$.publicKey").isEqualTo("ssh-ed25519 AAAA");
    }

    // ── ships dark -> 503 dark descriptor ──────────────────────────────────────────
    @Test
    void issue_dark_503_descriptor() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.issue(any(), eq("dev-1"), any()))
                .thenReturn(Mono.error(new AdminSshKeyIssuanceService.SshIssueDarkException()));
        asSuperadmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-1")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.dark").isEqualTo(true);
    }

    // ── service denial -> 403 ───────────────────────────────────────────────────────
    @Test
    void issue_serviceDeny_403() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.issue(any(), eq("dev-sa"), any()))
                .thenReturn(Mono.error(new AdminSshKeyIssuanceService.SshIssueDeniedException("nope")));
        asSuperadmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-sa")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
    }

    // ── private-key download: role + step-up + single-use ───────────────────────────
    @Test
    void download_nonSuperadmin_403() {
        asAdmin().get().uri("/bff/admin/ssh-issue/issued/ik-1/private-key")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(service, never()).downloadPrivateKey(any(), any());
    }

    @Test
    void download_missingStepUp_403() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().get().uri("/bff/admin/ssh-issue/issued/ik-1/private-key")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).downloadPrivateKey(any(), any());
    }

    @Test
    void download_firstTime_streamsAttachment() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        byte[] pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n"
                .getBytes(StandardCharsets.UTF_8);
        when(service.downloadPrivateKey(any(), eq("ik-1"))).thenReturn(Mono.just(pem));
        asSuperadmin().get().uri("/bff/admin/ssh-issue/issued/ik-1/private-key")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isOk()
                .expectHeader().value("Content-Disposition",
                        org.hamcrest.Matchers.containsString("hugmesh-ssh-ik-1"));
    }

    @Test
    void download_secondTime_410Gone() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.downloadPrivateKey(any(), eq("ik-1")))
                .thenReturn(Mono.error(new AdminSshKeyIssuanceService.SshIssueGoneException("gone")));
        asSuperadmin().get().uri("/bff/admin/ssh-issue/issued/ik-1/private-key")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isEqualTo(410);
    }

    @Test
    void download_dark_503() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.downloadPrivateKey(any(), eq("ik-1")))
                .thenReturn(Mono.error(new AdminSshKeyIssuanceService.SshIssueDarkException()));
        asSuperadmin().get().uri("/bff/admin/ssh-issue/issued/ik-1/private-key")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isEqualTo(503);
    }

    // ── revoke: role + step-up ──────────────────────────────────────────────────────
    @Test
    void revoke_nonSuperadmin_403() {
        asAdmin().delete().uri("/bff/admin/ssh-issue/issued/ik-1")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden();
        verify(service, never()).revoke(any(), any(), any());
    }

    @Test
    void revoke_missingStepUp_403() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().delete().uri("/bff/admin/ssh-issue/issued/ik-1")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).revoke(any(), any(), any());
    }

    @Test
    void revoke_withStepUp_ok() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.revoke(any(), eq("ik-1"), any())).thenReturn(Mono.just(1L));
        asSuperadmin().delete().uri("/bff/admin/ssh-issue/issued/ik-1")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.revoked").isEqualTo(true);
    }

    // ── list: ADMIN allowed (read), no step-up required ────────────────────────────
    @Test
    void list_admin_ok() {
        when(service.listForDevice(eq("dev-1"), any())).thenReturn(Flux.empty());
        when(service.isEnabled()).thenReturn(false);
        asAdmin().get().uri("/bff/admin/ssh-issue/devices/dev-1/issued-keys")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.deviceId").isEqualTo("dev-1")
                .jsonPath("$.enabled").isEqualTo(false);
    }

    @Test
    void list_user_403() {
        asUser().get().uri("/bff/admin/ssh-issue/devices/dev-1/issued-keys")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).listForDevice(anyString(), any());
    }

    // ── A5 co-equal MFA step-up leg (U2) ────────────────────────────────────────────
    // The mfaDarkByDefault() @BeforeEach proves DARK = byte-identical (every test above uses the
    // workload-token leg). These prove the fresh-MFA leg: a FRESH stamp satisfies step-up with NO
    // workload token, the device op still runs (license stays a SEPARATE downstream service check,
    // never bypassed), and the MFA stamp is consumed single-use.

    @Test
    void issue_freshMfa_noWorkloadToken_reachesService_andConsumesSingleUse() {
        // No workload token (header absent) -> the 2-arg token leg is unsatisfied; only the fresh
        // MFA stamp can carry step-up. The bff_session cookie supplies the opaque session token.
        when(stepUp.isSatisfied(any(), any())).thenReturn(false); // token leg never satisfies
        when(mfaStepUp.isFresh(eq("bff_sess1"))).thenReturn(Mono.just(true));
        when(service.issue(any(), eq("dev-1"), any())).thenReturn(Mono.just(
                new AdminSshKeyIssuanceService.IssueResult("ik-1", "SHA256:zzz",
                        "ssh-ed25519 AAAA", null, true)));
        asSuperadmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-1")
                .cookie("bff_session", "bff_sess1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.issuedKeyId").isEqualTo("ik-1");
        // The DEVICE op still runs — the own-domain + device_ssh_license precondition is a SEPARATE
        // downstream check inside service.issue(), NOT bypassed by the MFA leg.
        verify(service).issue(any(), eq("dev-1"), any());
        verify(mfaStepUp).consume(eq("bff_sess1"));
    }

    @Test
    void issue_freshMfa_deviceLicenseDenialStill403_notBypassed() {
        // A fresh MFA stamp satisfies STEP-UP only. The downstream device-license/own-domain wall
        // (SshIssueDeniedException) is STILL enforced and surfaces as 403 — MFA never bypasses it.
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        when(mfaStepUp.isFresh(eq("bff_sess1"))).thenReturn(Mono.just(true));
        when(service.issue(any(), eq("dev-sa"), any()))
                .thenReturn(Mono.error(new AdminSshKeyIssuanceService.SshIssueDeniedException(
                        "no active SSH license for this device")));
        asSuperadmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-sa")
                .cookie("bff_session", "bff_sess1")
                .exchange().expectStatus().isForbidden();
        verify(service).issue(any(), eq("dev-sa"), any());
    }

    @Test
    void issue_freshMfa_butActorBlocked_neverConsumes() {
        // The actor/role floor (@PreAuthorize hasRole SUPERADMIN) runs BEFORE the handler body, so
        // an ADMIN never reaches the MFA leg — nothing is consumed even with a fresh stamp.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(true));
        asAdmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-1")
                .cookie("bff_session", "bff_sess1")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).issue(any(), any(), any());
        verify(mfaStepUp, never()).consume(anyString());
    }

    @Test
    void privateKey_freshMfa_noWorkloadToken_streams_andConsumesSingleUse() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        when(mfaStepUp.isFresh(eq("bff_sess1"))).thenReturn(Mono.just(true));
        byte[] pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n"
                .getBytes(StandardCharsets.UTF_8);
        when(service.downloadPrivateKey(any(), eq("ik-1"))).thenReturn(Mono.just(pem));
        asSuperadmin().get().uri("/bff/admin/ssh-issue/issued/ik-1/private-key")
                .cookie("bff_session", "bff_sess1")
                .exchange().expectStatus().isOk()
                .expectHeader().value("Content-Disposition",
                        org.hamcrest.Matchers.containsString("hugmesh-ssh-ik-1"));
        verify(mfaStepUp).consume(eq("bff_sess1"));
    }

    @Test
    void revoke_freshMfa_noWorkloadToken_ok_andConsumesSingleUse() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        when(mfaStepUp.isFresh(eq("bff_sess1"))).thenReturn(Mono.just(true));
        when(service.revoke(any(), eq("ik-1"), any())).thenReturn(Mono.just(1L));
        asSuperadmin().delete().uri("/bff/admin/ssh-issue/issued/ik-1")
                .cookie("bff_session", "bff_sess1")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.revoked").isEqualTo(true);
        verify(mfaStepUp).consume(eq("bff_sess1"));
    }

    // ── STRUCTURED STEP-UP SIGNAL on the real wire (gate #1 of 3: SshKeyIssue) ─────────
    // Before the signal existed the browser could only sniff the free-text message, so a reword
    // silently killed the inline MFA dialog. These prove the header IS on a step-up 403, is
    // ABSENT on the ordinary 403s this same controller emits, and that the legacy phrase — the
    // old-UI fallback — is still there verbatim.

    @Test
    void issue_missingStepUp_carriesTheStructuredSignal_namingSshKeyIssueFlavour() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-1")
                .exchange().expectStatus().isForbidden()
                .expectHeader().valueEquals(StepUpRequiredException.SIGNAL_HEADER,
                        SshKeyIssueStepUpGate.STEP_UP_HEADER)
                // The old-UI fallback phrase is pinned as a HARD-CODED literal on purpose: an
                // assertion written against StepUpRequiredException.LEGACY_PHRASE would follow a
                // reword of that constant and silently stop protecting old clients.
                .expectBody().jsonPath("$.error").isEqualTo(
                        "issue requires step-up re-authentication (present X-SshKeyIssue-StepUp)");
        verify(service, never()).issue(any(), any(), any());
    }

    @Test
    void download_missingStepUp_carriesTheStructuredSignal() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().get().uri("/bff/admin/ssh-issue/issued/ik-1/private-key")
                .exchange().expectStatus().isForbidden()
                .expectHeader().valueEquals(StepUpRequiredException.SIGNAL_HEADER,
                        SshKeyIssueStepUpGate.STEP_UP_HEADER);
    }

    @Test
    void revoke_missingStepUp_carriesTheStructuredSignal() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().delete().uri("/bff/admin/ssh-issue/issued/ik-1")
                .exchange().expectStatus().isForbidden()
                .expectHeader().valueEquals(StepUpRequiredException.SIGNAL_HEADER,
                        SshKeyIssueStepUpGate.STEP_UP_HEADER);
    }

    @Test
    void ordinaryLicenseDeny403_hasNoStepUpSignal_soNoMfaPromptPops() {
        // THE negative. Step-up IS satisfied; the service refuses for an unrelated reason
        // (SshIssueDeniedException -> ApiException.forbidden). A browser must show the error, not
        // an MFA dialog.
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.issue(any(), eq("dev-sa"), any()))
                .thenReturn(Mono.error(new AdminSshKeyIssuanceService.SshIssueDeniedException(
                        "no active SSH license for this device")));
        asSuperadmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-sa")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden()
                .expectHeader().doesNotExist(StepUpRequiredException.SIGNAL_HEADER);
    }

    @Test
    void roleFloor403_hasNoStepUpSignal() {
        // A second negative flavour: Spring Security's own 403 (@PreAuthorize), which never goes
        // through ApiExceptionHandler at all.
        asAdmin().post().uri("/bff/admin/ssh-issue/issue?deviceId=dev-1")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isForbidden()
                .expectHeader().doesNotExist(StepUpRequiredException.SIGNAL_HEADER);
    }

    @Test
    void nonStepUpErrorStatuses_neverCarryTheSignal() {
        // 400 (missing deviceId), 503 (dark), 410 (single-use burned) — all reached WITH step-up
        // satisfied, so none may look like a step-up prompt to the client.
        when(stepUp.isSatisfied(any(), any())).thenReturn(true);
        asSuperadmin().post().uri("/bff/admin/ssh-issue/issue")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isBadRequest()
                .expectHeader().doesNotExist(StepUpRequiredException.SIGNAL_HEADER);

        when(service.downloadPrivateKey(any(), eq("ik-1")))
                .thenReturn(Mono.error(new AdminSshKeyIssuanceService.SshIssueGoneException("gone")));
        asSuperadmin().get().uri("/bff/admin/ssh-issue/issued/ik-1/private-key")
                .header(STEP_UP, TOKEN).exchange().expectStatus().isEqualTo(410)
                .expectHeader().doesNotExist(StepUpRequiredException.SIGNAL_HEADER);
    }

    @SuppressWarnings("unused")
    private static DataBuffer buf(String s) {
        return new DefaultDataBufferFactory().wrap(s.getBytes(StandardCharsets.UTF_8));
    }
}
