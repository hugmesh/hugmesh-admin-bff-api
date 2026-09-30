package net.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * {@code POST /bff/internal/domains/{clusterDomain}/reconcile-ack} — the node agent's report-back
 * at exactly the path and body hugmesh-generator {@code hugmesh-domain-reconcile:ack_generation}
 * already sends (decision 89b, hugmesh-admin-bff-api#6 item 3), with the internal token ARMED.
 * The database half (monotonic generation, unknown domain, {@code ca_provisioned} untouched) is
 * {@link DomainRegistryAckAndAllocateTest}.
 */
@WebFluxTest(controllers = DomainRegistryInternalController.class,
        excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE,
                classes = net.hugmesh.authcore.config.InternalTokenWebFilter.class))
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
@TestPropertySource(properties = {
        "app.internal.token=s3cret",
        "app.internal.token-header=X-Internal-Token"
})
class DomainRegistryInternalControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @MockitoBean DomainRegistryService service;
    @MockitoBean DomainRegistryExportService export;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    static final String ACK = "/bff/internal/domains/acme.test/reconcile-ack";
    /** The agent's body, byte for byte what its jq builds: {caProvisioned, appsetRegistered, generation}. */
    static final String AGENT_BODY = "{\"caProvisioned\":true,\"appsetRegistered\":true,\"generation\":7}";

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient.RequestHeadersSpec<?> post(String body) {
        return web.post().uri(ACK).header("X-Internal-Token", "s3cret")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(body);
    }

    @Test
    void ack_withToken_advances_andReportsApplied() {
        when(service.recordReconcileAck("acme.test", true, 7L)).thenReturn(Mono.just(true));
        post(AGENT_BODY).exchange().expectStatus().isOk().expectBody()
                .jsonPath("$.clusterDomain").isEqualTo("acme.test")
                .jsonPath("$.applied").isEqualTo(true);
        // caProvisioned:true rode along and reached NOTHING: the service has no parameter for it
        // (decision 87a = B), so appsetRegistered + generation are the whole write.
        verify(service).recordReconcileAck("acme.test", true, 7L);
    }

    @Test
    void ack_staleGeneration_is200_notApplied() {
        when(service.recordReconcileAck("acme.test", true, 7L)).thenReturn(Mono.just(false));
        post(AGENT_BODY).exchange().expectStatus().isOk().expectBody()
                .jsonPath("$.applied").isEqualTo(false);
    }

    @Test
    void ack_unknownDomain_is404() {
        when(service.recordReconcileAck(eq("acme.test"), anyBoolean(), anyLong()))
                .thenReturn(Mono.error(ApiException.notFound("no domain registered")));
        post(AGENT_BODY).exchange().expectStatus().isNotFound();
    }

    @Test
    void ack_missingGeneration_is400_andNeverWrites() {
        post("{\"caProvisioned\":false,\"appsetRegistered\":true}").exchange()
                .expectStatus().isBadRequest();
        verify(service, never()).recordReconcileAck(anyString(), anyBoolean(), anyLong());
    }

    @Test
    void ack_negativeGeneration_is400_andNeverWrites() {
        post("{\"appsetRegistered\":true,\"generation\":-1}").exchange()
                .expectStatus().isBadRequest();
        verify(service, never()).recordReconcileAck(anyString(), anyBoolean(), anyLong());
    }

    @Test
    void ack_missingAppsetRegistered_is400_andNeverWrites() {
        post("{\"caProvisioned\":true,\"generation\":3}").exchange()
                .expectStatus().isBadRequest();
        verify(service, never()).recordReconcileAck(anyString(), anyBoolean(), anyLong());
    }

    @Test
    void ack_withoutToken_is401() {
        web.post().uri(ACK).contentType(MediaType.APPLICATION_JSON).bodyValue(AGENT_BODY)
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).recordReconcileAck(anyString(), anyBoolean(), anyLong());
    }

    @Test
    void ack_asHumanSuperadmin_is403() {
        web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")))
                .post().uri(ACK).contentType(MediaType.APPLICATION_JSON).bodyValue(AGENT_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).recordReconcileAck(anyString(), anyBoolean(), anyLong());
    }
}
