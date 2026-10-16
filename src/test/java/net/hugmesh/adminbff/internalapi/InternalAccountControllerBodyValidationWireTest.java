package net.hugmesh.adminbff.internalapi;

import net.hugmesh.adminbff.account.AccountCasdoorSubService;
import net.hugmesh.adminbff.account.AccountIssuerService;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.account.RegistrationDomainResolver;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.authcore.account.Account;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.commons.security.DomainRegistry;
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
import reactor.core.publisher.Mono;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Wire-level pin that the four internal request bodies' {@code @NotBlank} constraints are
 * ENFORCED (hugmesh-admin-bff-api#107): {@code POST /bff/internal/accounts/ensure},
 * {@code /sessions}, {@code /custody/stamp} and {@code /session/exchange}. The class-level
 * {@code @Validated} on {@link InternalAccountController} does NOT cover a {@code @RequestBody}
 * record, so each parameter needs its own {@code @Valid}; before it, a missing or blank value
 * reached the handler (and, against the real {@code AccountStore}, the database). Same slice as
 * {@link InternalAccountControllerRecordUsageWireTest}: real {@link SecurityConfig} and real
 * {@link ValidationExceptionHandler}, every collaborator mocked, no database, no docker.
 *
 * <p>Each endpoint has a positive control (a well-formed body still reaches the handler and
 * gets its normal status), so a 400 here can only come from validation, and the rejection
 * cases assert the {@code {"error":"validation failed","fields":{...}}} body and that NO
 * collaborator was touched. Removing {@code @Valid} from any one parameter turns that
 * endpoint's rejection tests red.
 *
 * <p>{@code /session/exchange} checks the custody cipher FIRST in the handler body (503
 * "custody disabled"; this slice has no cipher bean, so a well-formed body is a 503). Bean
 * validation runs during argument resolution, BEFORE the handler, so a blank token is a 400
 * even with the cipher unavailable: the control for that endpoint is the 503, and the mutant
 * for it reads 503 where the fixed code reads 400.
 */
@WebFluxTest(controllers = InternalAccountController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class InternalAccountControllerBodyValidationWireTest {

    @Autowired ApplicationContext context;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean AccountStore accounts;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean MfaStepUpService mfaStepUp;
    @MockitoBean AccountLocalpartService localparts;
    @MockitoBean AccountCasdoorSubService casdoorSubs;
    @MockitoBean AccountIssuerService accountIssuers;
    @MockitoBean RegistrationDomainResolver registrationDomains;
    @MockitoBean UsageService usage;

    WebTestClient service;

    private static final Account ACCOUNT =
            new Account("google:a@x.com", "google", "a@x.com", false, List.of("user"));

    @BeforeEach
    void setUp() {
        when(localparts.resolveAndPersist(any(), any())).thenReturn(Mono.just("a"));
        when(localparts.localpartsOf(any()))
                .thenReturn(Mono.just(new AccountLocalpartService.ResolvedLocalparts("", "")));
        service = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build()
                .mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_SERVICE")));
    }

    private WebTestClient.ResponseSpec post(String uri, String json) {
        return service.post().uri(uri)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(json).exchange();
    }

    /** No collaborator of the controller may have been touched by a rejected body. */
    private void verifyNothingCalled() {
        verifyNoInteractions(accounts, localparts, casdoorSubs, accountIssuers, suspensions);
    }

    // ───────────────────────────── POST /bff/internal/accounts/ensure ─────────────────────────────

    @Test
    void ensure_wellFormed_reachesTheHandler_200() {
        when(accounts.ensureAccount("google", "a@x.com")).thenReturn(Mono.just(ACCOUNT));
        post("/bff/internal/accounts/ensure", "{\"provider\":\"google\",\"handle\":\"a@x.com\"}")
                .expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo("google:a@x.com");
        verify(accounts).ensureAccount("google", "a@x.com");
    }

    @Test
    void ensure_emptyObject_is400_validationFailed_namingBothFields_andNothingIsCalled() {
        post("/bff/internal/accounts/ensure", "{}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.provider").exists()
                .jsonPath("$.fields.handle").exists();
        verifyNothingCalled();
    }

    @Test
    void ensure_blankStrings_is400_validationFailed_andNothingIsCalled() {
        post("/bff/internal/accounts/ensure", "{\"provider\":\"\",\"handle\":\"   \"}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.provider").exists()
                .jsonPath("$.fields.handle").exists();
        verifyNothingCalled();
    }

    // ───────────────────────────── POST /bff/internal/sessions ─────────────────────────────

    @Test
    void sessions_wellFormed_reachesTheHandler_200() {
        when(accounts.account("google:a@x.com")).thenReturn(Mono.just(ACCOUNT));
        when(accounts.newSession(ACCOUNT)).thenReturn(Mono.just("bff_tok"));
        post("/bff/internal/sessions", "{\"accountId\":\"google:a@x.com\"}")
                .expectStatus().isOk()
                .expectBody().jsonPath("$.token").isEqualTo("bff_tok");
        verify(accounts).account("google:a@x.com");
    }

    @Test
    void sessions_emptyObject_is400_validationFailed_andNothingIsCalled() {
        post("/bff/internal/sessions", "{}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.accountId").exists();
        verifyNothingCalled();
    }

    @Test
    void sessions_blankAccountId_is400_validationFailed_andNothingIsCalled() {
        post("/bff/internal/sessions", "{\"accountId\":\"\"}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.accountId").exists();
        verifyNothingCalled();
    }

    // ───────────────────────────── POST /bff/internal/custody/stamp ─────────────────────────────

    @Test
    void stamp_wellFormed_reachesTheHandler_204() {
        when(accounts.stampCustody(eq("bff_tok"), eq("ENC-ACCESS"), eq(null), any()))
                .thenReturn(Mono.just(1L));
        post("/bff/internal/custody/stamp",
                "{\"sessionToken\":\"bff_tok\",\"encAccess\":\"ENC-ACCESS\","
                        + "\"encRefresh\":null,\"expiresInSeconds\":900}")
                .expectStatus().isNoContent();
        verify(accounts).stampCustody(eq("bff_tok"), eq("ENC-ACCESS"), eq(null), any());
    }

    @Test
    void stamp_emptyObject_is400_andNothingIsCalled() {
        // The issue measured a GENERIC 400 here before the fix (Jackson refusing the missing
        // primitive), not the validation body; the status alone cannot tell the two apart, so
        // the blank-strings test below (every primitive present) is the one that pins @Valid.
        post("/bff/internal/custody/stamp", "{}")
                .expectStatus().isBadRequest();
        verifyNothingCalled();
    }

    @Test
    void stamp_blankStrings_is400_validationFailed_namingBothFields_andNothingIsCalled() {
        post("/bff/internal/custody/stamp",
                "{\"sessionToken\":\"\",\"encAccess\":\"  \",\"expiresInSeconds\":900}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.sessionToken").exists()
                .jsonPath("$.fields.encAccess").exists();
        verifyNothingCalled();
    }

    @Test
    void stamp_nullStrings_is400_validationFailed_andNothingIsCalled() {
        post("/bff/internal/custody/stamp",
                "{\"sessionToken\":null,\"encAccess\":null,\"expiresInSeconds\":900}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.sessionToken").exists()
                .jsonPath("$.fields.encAccess").exists();
        verifyNothingCalled();
    }

    // ───────────────────────────── POST /bff/internal/session/exchange ─────────────────────────────

    @Test
    void exchange_wellFormed_reachesTheHandler_whichRefusesWith503_noCipherInThisSlice() {
        post("/bff/internal/session/exchange", "{\"token\":\"bff_tok\"}")
                .expectStatus().isEqualTo(503);
        verifyNothingCalled();
    }

    @Test
    void exchange_emptyObject_is400_notTheCipherCheck503() {
        post("/bff/internal/session/exchange", "{}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.token").exists();
        verifyNothingCalled();
    }

    @Test
    void exchange_blankToken_is400_notTheCipherCheck503() {
        post("/bff/internal/session/exchange", "{\"token\":\"\"}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.token").exists();
        verifyNothingCalled();
    }
}
