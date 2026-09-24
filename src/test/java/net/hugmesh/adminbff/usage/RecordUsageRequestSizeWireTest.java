package net.hugmesh.adminbff.usage;

import net.hugmesh.adminbff.account.AccountCasdoorSubService;
import net.hugmesh.adminbff.account.AccountIssuerService;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.account.RegistrationDomainResolver;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.internalapi.InternalAccountController;
import net.hugmesh.adminbff.suspension.SuspensionService;
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
 * hugmesh-admin-bff-api#105's own done-when: {@code POST /bff/internal/usage} LENGTH-caps
 * {@code handle} (400) and {@code action} (128), so the issue's 200 KB handle is a {@code 400
 * validation failed} and never reaches {@link UsageService}'s in-memory log. The lengths are
 * pinned as literals on purpose: widening a cap must fail this test. RED on the pre-fix code
 * (only {@code @NotBlank}: a 200 KB handle was 204 and stored). Same slice as
 * {@code InternalAccountControllerRecordUsageWireTest} (real SecurityConfig and validation
 * handler, collaborators mocked, no docker).
 */
@WebFluxTest(controllers = InternalAccountController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class RecordUsageRequestSizeWireTest {

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

    private WebTestClient.ResponseSpec post(String handle, String action) {
        String json = "{\"handle\":\"" + handle + "\",\"roles\":[\"user\"],\"action\":\"" + action + "\"}";
        return service.post().uri("/bff/internal/usage")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(json).exchange();
    }

    @Test
    void theIssuesTwoHundredKilobyteHandle_is400_andNothingIsRecorded() {
        post("h".repeat(200 * 1024 - 64), "register")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.handle").exists();
        verify(usage, never()).record(any(), any(), any());
    }

    @Test
    void handleOf401_is400_handleOf400_is204() {
        post("a".repeat(401), "register").expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.handle").exists();
        verify(usage, never()).record(any(), any(), any());

        String max = "a".repeat(400);
        post(max, "register").expectStatus().isNoContent();
        verify(usage).record(max, List.of("user"), "register");
    }

    @Test
    void actionOf129_is400_actionOf128_is204() {
        post("alice@example.test", "x".repeat(129)).expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.action").exists();
        verify(usage, never()).record(any(), any(), any());

        String max = "x".repeat(128);
        post("alice@example.test", max).expectStatus().isNoContent();
        verify(usage).record("alice@example.test", List.of("user"), max);
    }
}
