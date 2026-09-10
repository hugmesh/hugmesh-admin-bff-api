package net.hugmesh.adminbff.servicecatalog;
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
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;

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
 * The App-Store CURATION controller role matrix — the acceptance bar for the SUPERADMIN-ONLY
 * boundary on {@code /bff/superadmin/service-store}. Mirrors {@code DomainRegistryControllerTest}:
 * {@code @WebFluxTest} + the real {@link SecurityConfig} so BOTH the coarse path gate
 * ({@code /bff/superadmin/** = hasRole SUPERADMIN}) AND the per-method
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} run.
 *
 * <ul>
 *   <li>SUPERADMIN — ALLOW on list / offer / withdraw; {@code curated_by_subject} stamped
 *       from the JWT subject (never the body).</li>
 *   <li>ADMIN — DENY (403) on EVERY endpoint (passes the coarse {@code /bff/admin} gate but
 *       NOT the SUPERADMIN-only {@code /bff/superadmin} gate) + never reaches the service.</li>
 *   <li>MOD / USER — DENY (403) on EVERY endpoint + never reaches the service.</li>
 * </ul>
 *
 * <p>Since the step-up gate landed on {@code offer}, the SUPERADMIN role is necessary but no
 * longer sufficient THERE: a superadmin with no {@code X-ServiceStore-StepUp} token and no fresh
 * MFA stamp is refused with the "requires step-up" 403 the merged catalog-ui slice keys its
 * {@code <hug-step-up-challenge>} on, and the service is never called.
 *
 * <p><b>{@code withdraw} is ROLE-ONLY</b> — operator decision "role only" (hugmesh-generator #347,
 * 2026-09-10), reversing the gate that landed with #51. The tests below assert the ABSENCE of the
 * gate positively rather than by omission: a superadmin with the gate mock refusing everything
 * still gets a 200 and a real write, no {@code X-Step-Up-Required} header is minted, and neither
 * {@code ServiceStoreStepUpGate} nor {@code MfaStepUpService} is consulted at all. That last
 * assertion is the one that fails if anyone re-adds the gate — an allow-path test that merely
 * sends a valid token would keep passing either way. {@code list} stays role-only too — it is a
 * read. Because the role is now the WHOLE protection on withdraw, the deny matrix below covers
 * admin, mod AND user on that verb, not just admin.
 */
@WebFluxTest(controllers = ServiceCurationController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class ServiceCurationControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ServiceCurationService service;
    @MockitoBean ServiceStoreStepUpGate stepUp;
    @MockitoBean net.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String SUBJECT = "superadmin-subject-7";
    private static final String STEP_UP = ServiceStoreStepUpGate.STEP_UP_HEADER;
    private static final String TOKEN = "good-token";

    @BeforeEach
    void mfaDarkByDefault() {
        // A5 MFA leg ships DARK: no fresh stamp, nothing to consume — only the workload step-up
        // token leg satisfies. The 3-arg unified gate delegates to the 2-arg token leg.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(SUBJECT))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
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

    private static ServiceCuration sample(String domain, String key) {
        return new ServiceCuration("cur-1", domain, key, ServiceCuration.STATE_OFFERED,
                SUBJECT, Instant.now(), Instant.now());
    }

    private static final String OFFER_BODY = "{\"serviceKey\":\"owncast\"}";

    // ── SUPERADMIN ALLOW ────────────────────────────────────────────────────────

    @Test
    void list_asSuperadmin_isAllowed() {
        when(service.listForDomain(eq("acme.test"))).thenReturn(Flux.just(sample("acme.test", "owncast")));
        asSuperadmin().get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].serviceKey").isEqualTo("owncast");
        verify(service).listForDomain("acme.test");
    }

    @Test
    void offer_asSuperadmin_withStepUp_isAllowed_andStampsSubjectFromToken() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        when(service.offer(eq("acme.test"), eq("owncast"), eq(SUBJECT)))
                .thenReturn(Mono.just(sample("acme.test", "owncast")));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.serviceKey").isEqualTo("owncast")
                .jsonPath("$.state").isEqualTo("offered");
        // domain from the PATH, subject from the TOKEN — never the body.
        verify(service).offer("acme.test", "owncast", SUBJECT);
    }

    /** ROLE-ONLY withdraw, stated the way that can actually fail: the step-up gate mock refuses
     *  EVERYTHING and no token is sent, and the write still happens. The subject is still stamped
     *  from the JWT, and the domain still comes from the path. */
    @Test
    void withdraw_asSuperadmin_isAllowed_withNoStepUpTokenAndTheGateRefusingEverything() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean())).thenReturn(false);
        ServiceCuration withdrawn = new ServiceCuration("cur-1", "acme.test", "owncast",
                ServiceCuration.STATE_WITHDRAWN, SUBJECT, Instant.now(), Instant.now());
        when(service.withdraw(eq("acme.test"), eq("owncast"), eq(SUBJECT)))
                .thenReturn(Mono.just(withdrawn));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/withdraw")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isOk()
                .expectHeader().doesNotExist("X-Step-Up-Required")
                .expectBody().jsonPath("$.state").isEqualTo("withdrawn");
        // domain from the PATH, subject from the TOKEN — never the body.
        verify(service).withdraw("acme.test", "owncast", SUBJECT);
    }

    /** The structural half of the same decision, and the assertion a re-added gate trips FIRST:
     *  the withdraw path must not TOUCH the step-up machinery. A gate re-added in any shape has to
     *  ask one of these two collaborators something, so this fails even for a gate that would let
     *  the request through. */
    @Test
    void withdraw_asSuperadmin_neverConsultsTheStepUpGateOrTheMfaStamp() {
        when(service.withdraw(eq("acme.test"), eq("owncast"), eq(SUBJECT)))
                .thenReturn(Mono.just(new ServiceCuration("cur-1", "acme.test", "owncast",
                        ServiceCuration.STATE_WITHDRAWN, SUBJECT, Instant.now(), Instant.now())));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/withdraw")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isOk();
        verify(service).withdraw("acme.test", "owncast", SUBJECT);
        verify(stepUp, never()).isSatisfied(anyString(), any(), anyBoolean());
        verify(mfaStepUp, never()).isFresh(any());
        verify(mfaStepUp, never()).consume(any());
    }

    /** A token the operator confirmed for an EARLIER offer challenge is still sent by the merged
     *  catalog-ui on every later call from that view. It must be inert here, not a 400 for an
     *  unexpected header and not a second gate. */
    @Test
    void withdraw_asSuperadmin_ignoresAStaleStepUpTokenOnTheWire() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        when(service.withdraw(eq("acme.test"), eq("owncast"), eq(SUBJECT)))
                .thenReturn(Mono.just(new ServiceCuration("cur-1", "acme.test", "owncast",
                        ServiceCuration.STATE_WITHDRAWN, SUBJECT, Instant.now(), Instant.now())));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/withdraw")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .header(STEP_UP, "a-stale-token-from-an-earlier-offer")
                .exchange().expectStatus().isOk();
        verify(service).withdraw("acme.test", "owncast", SUBJECT);
    }

    @Test
    void offer_blankServiceKey_isBadRequest_andNeverWrites() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"serviceKey\":\"\"}")
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).offer(anyString(), anyString(), anyString());
    }

    // ── STEP-UP: superadmin is necessary but NOT sufficient on the mutating verbs ─

    /** The denial the merged catalog-ui slice consumes: 403 + the "requires step-up" phrase its
     *  {@code ServiceCatalogApiError.isStepUpRequired} matches (status 403 AND
     *  {@code /requires step-up/i}), plus the structured {@code X-Step-Up-Required} signal naming
     *  the retry header. Without this the challenge component can never render. */
    @Test
    void offer_asSuperadmin_withoutStepUp_is403WithTheChallengeContract_andNeverWrites() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isForbidden()
                .expectHeader().valueEquals("X-Step-Up-Required", STEP_UP)
                .expectBody().jsonPath("$.error").value(org.hamcrest.Matchers.matchesPattern(
                        "(?i).*requires step-up.*"));
        verify(service, never()).offer(anyString(), anyString(), anyString());
    }

    /** The inverse of the offer test above, and the exact behaviour the operator asked for: on
     *  withdraw the SAME token-less superadmin request that offer refuses must SUCCEED, and must
     *  NOT carry the challenge contract the catalog-ui keys on — otherwise the UI would render a
     *  challenge for an operation that no longer has one. */
    @Test
    void withdraw_asSuperadmin_withoutStepUp_isNOT403_andCarriesNoChallengeContract() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        when(service.withdraw(eq("acme.test"), eq("owncast"), eq(SUBJECT)))
                .thenReturn(Mono.just(new ServiceCuration("cur-1", "acme.test", "owncast",
                        ServiceCuration.STATE_WITHDRAWN, SUBJECT, Instant.now(), Instant.now())));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/withdraw")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isOk()
                .expectHeader().doesNotExist("X-Step-Up-Required")
                .expectBody().jsonPath("$.state").isEqualTo("withdrawn");
        verify(service).withdraw("acme.test", "owncast", SUBJECT);
    }

    @Test
    void offer_withAWrongStepUpToken_is403_andNeverWrites() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);   // only THIS token is valid
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .header(STEP_UP, "stale-token")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).offer(anyString(), anyString(), anyString());
    }

    /** The co-equal MFA leg: a FRESH Casdoor stamp satisfies with no token, and is CONSUMED so the
     *  next privileged mutation needs its own challenge. */
    @Test
    void offer_withFreshMfaAndNoToken_isAllowed_andConsumesTheStamp() {
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(true));
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);      // the token leg says no
        when(service.offer(eq("acme.test"), eq("owncast"), eq(SUBJECT)))
                .thenReturn(Mono.just(sample("acme.test", "owncast")));
        asSuperadmin().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isOk();
        verify(service).offer("acme.test", "owncast", SUBJECT);
        verify(mfaStepUp).consume(any());
    }

    /** list is a READ and must NOT have grown a step-up requirement. */
    @Test
    void list_asSuperadmin_needsNoStepUp() {
        when(stepUp.isSatisfied(any(), any())).thenReturn(false);
        when(service.listForDomain(eq("acme.test")))
                .thenReturn(Flux.just(sample("acme.test", "owncast")));
        asSuperadmin().get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isOk();
        verify(service).listForDomain("acme.test");
    }

    // ── ADMIN DENY (403) on EVERY endpoint + never reaches the service ───────────

    @Test
    void list_asAdmin_isForbidden() {
        asAdmin().get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).listForDomain(anyString());
    }

    @Test
    void offer_asAdmin_isForbidden_andNeverWrites() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);   // the ROLE is what denies
        asAdmin().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).offer(anyString(), anyString(), anyString());
    }

    /** withdraw is role-only, so the role gate is the ENTIRE protection — no token is sent here,
     *  because there is no longer a second gate that could be the thing doing the denying. */
    @Test
    void withdraw_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/superadmin/service-store/acme.test/withdraw")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).withdraw(anyString(), anyString(), anyString());
    }

    // ── MOD DENY (403) ──────────────────────────────────────────────────────────

    @Test
    void offer_asMod_isForbidden_andNeverWrites() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);   // the ROLE is what denies
        asMod().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).offer(anyString(), anyString(), anyString());
    }

    /** Role-only means the whole non-superadmin matrix has to be covered on this verb, not just
     *  admin — there is no step-up gate left to catch a role check that regressed. */
    @Test
    void withdraw_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/superadmin/service-store/acme.test/withdraw")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).withdraw(anyString(), anyString(), anyString());
    }

    @Test
    void list_asMod_isForbidden() {
        asMod().get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isForbidden();
    }

    // ── USER DENY (403) ─────────────────────────────────────────────────────────

    @Test
    void offer_asUser_isForbidden_andNeverWrites() {
        when(stepUp.isSatisfied(any(), eq(TOKEN))).thenReturn(true);   // the ROLE is what denies
        asUser().post().uri("/bff/superadmin/service-store/acme.test/offer")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .header(STEP_UP, TOKEN)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).offer(anyString(), anyString(), anyString());
    }

    @Test
    void withdraw_asUser_isForbidden_andNeverWrites() {
        asUser().post().uri("/bff/superadmin/service-store/acme.test/withdraw")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(OFFER_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).withdraw(anyString(), anyString(), anyString());
    }

    @Test
    void list_asUser_isForbidden() {
        asUser().get().uri("/bff/superadmin/service-store/acme.test")
                .exchange().expectStatus().isForbidden();
    }
}
