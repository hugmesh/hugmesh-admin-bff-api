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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Wire-level contract of {@code POST /bff/internal/usage} (decision 55, hugmesh-admin-bff-api#85)
 * — the shape hugmesh-user-bff-api#19 codes against. The unit tests in {@link
 * InternalAccountControllerTest} call the handler method directly and so cannot see two things
 * only the web layer decides: the response STATUS (204, not the 200 a {@code Mono<Void>} would
 * otherwise render) and whether the record's {@code @NotBlank} constraints are ENFORCED. The
 * second is the load-bearing pin: with the class-level {@code @Validated} alone a {@code
 * @RequestBody} record's constraints are inert (the four sibling bodies were that way until #107;
 * see {@link InternalAccountControllerBodyValidationWireTest}),
 * and a body with no {@code action} would reach {@code UsageService.moduleOf(null)} and NPE
 * into a 500 — so {@link InternalAccountController#recordUsage} takes the body {@code @Valid},
 * and this class goes RED if that annotation is removed. Real {@link SecurityConfig} and real
 * {@link ValidationExceptionHandler}; every collaborator mocked; no database, no docker. The
 * role gate on the prefix is pinned by {@code InternalSurfaceRoleMatrixTest}, not here.
 */
@WebFluxTest(controllers = InternalAccountController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class InternalAccountControllerRecordUsageWireTest {

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

    @BeforeEach
    void setUp() {
        when(usage.record(any(), any(), any())).thenReturn(Mono.empty());
        service = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build()
                .mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_SERVICE")));
    }

    private WebTestClient.ResponseSpec post(String json) {
        return service.post().uri("/bff/internal/usage")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(json).exchange();
    }

    @Test
    void wellFormedBody_is204NoContent_andForwardsTheExactTriple() {
        post("{\"handle\":\"alice@example.test\",\"roles\":[\"user\"],\"action\":\"register\"}")
                .expectStatus().isNoContent()
                .expectBody().isEmpty();
        verify(usage).record("alice@example.test", List.of("user"), "register");
    }

    @Test
    void omittedRoles_is204_andForwardsAnEmptyList() {
        post("{\"handle\":\"bob@example.test\",\"action\":\"login\"}")
                .expectStatus().isNoContent();
        verify(usage).record("bob@example.test", List.of(), "login");
    }

    @Test
    void emptyObject_is400_validationFailed_namingBothFields_andNothingIsRecorded() {
        post("{}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.handle").exists()
                .jsonPath("$.fields.action").exists();
        verify(usage, never()).record(any(), any(), any());
    }

    @Test
    void missingAction_is400_notA500FromModuleOfNull() {
        // Without @Valid this body reaches UsageService.moduleOf(null) and NPEs into a 500.
        post("{\"handle\":\"carol@example.test\",\"roles\":[]}")
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.action").exists();
        verify(usage, never()).record(any(), any(), any());
    }

    @Test
    void blankHandle_is400_neverAJunkRow() {
        post("{\"handle\":\"   \",\"roles\":[\"user\"],\"action\":\"register\"}")
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.handle").exists();
        verify(usage, never()).record(any(), any(), any());
    }

    @Test
    void blankAction_is400() {
        post("{\"handle\":\"dave@example.test\",\"action\":\"\"}")
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.action").exists();
        verify(usage, never()).record(any(), any(), any());
    }

    @Test
    void rolesNotAList_is400_andNothingIsRecorded() {
        post("{\"handle\":\"erin@example.test\",\"roles\":\"user\",\"action\":\"register\"}")
                .expectStatus().isBadRequest();
        verify(usage, never()).record(any(), any(), any());
    }
}
