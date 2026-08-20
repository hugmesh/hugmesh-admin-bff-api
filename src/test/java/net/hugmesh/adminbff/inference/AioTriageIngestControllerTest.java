package net.hugmesh.adminbff.inference;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The web-layer contract for the in-cluster signal collector's entry point into
 * {@link AioTriageService} — the caller the AIOps feature shipped without.
 *
 * <ul>
 *   <li><b>NO CASDOOR JWT REQUIRED</b>: a collector POST with no Casdoor token is accepted —
 *       {@code /bff/internal/**} is gated to {@code ROLE_SERVICE}, which the collector
 *       satisfies with {@code X-Internal-Token}; this slice leaves the credential UNARMED
 *       (dev/test parity). Armed matrix: {@code InternalSurfaceRoleMatrixTest}.</li>
 *   <li><b>The batch reaches the service verbatim</b> — domain, recipient list, event key and
 *       raw signals, so a silently-null bind cannot pass a vacuous 200.</li>
 *   <li><b>Dark edge-AI is a 200, not an error</b>: the disabled/degraded sentinel yields
 *       {@code alerted:0} (fail-open — a stalled inference node never fails the collector).</li>
 *   <li><b>Fail-closed body</b>: a blank tenant, an empty recipient list, a blank recipient
 *       and a blank event key are clean 400s that never reach the service.</li>
 * </ul>
 */
@WebFluxTest(controllers = AioTriageIngestController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class})
class AioTriageIngestControllerTest {

    private static final String PATH = "/bff/internal/aio-triage/ingest";

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean AioTriageService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    /** The collector shape: the tenant, its admin recipients, a stable batch key, raw signals. */
    private static final String COLLECTOR_BODY = """
            {"domain":"brandx",
             "adminSubjects":["google:admin1@example.org","google:admin2@example.org"],
             "eventKey":"snort:rule-123:2026-08-20T12:00:00Z",
             "signals":"[Snort] 1:2000419 ET POLICY suspicious inbound to mySQL port 3306"}""";

    @Test
    void ingest_noJwt_isAccepted_andTheBatchReachesTheService() {
        when(service.triageAndNotify(anyString(), anyList(), anyString(), anyString()))
                .thenReturn(Mono.just(2L));

        // NO .mutateWith(mockJwt()) — the collector presents mTLS + X-Internal-Token, never a
        // human Casdoor token; this slice configures no app.internal.token (UNARMED parity).
        web.post().uri(PATH).contentType(MediaType.APPLICATION_JSON).bodyValue(COLLECTOR_BODY)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.accepted").isEqualTo(true)
                .jsonPath("$.alerted").isEqualTo(2);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> admins = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<String> domain = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> eventKey = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> signals = ArgumentCaptor.forClass(String.class);
        verify(service).triageAndNotify(domain.capture(), admins.capture(),
                eventKey.capture(), signals.capture());
        assertThat(domain.getValue()).isEqualTo("brandx");
        assertThat(admins.getValue())
                .containsExactly("google:admin1@example.org", "google:admin2@example.org");
        assertThat(eventKey.getValue()).isEqualTo("snort:rule-123:2026-08-20T12:00:00Z");
        assertThat(signals.getValue()).startsWith("[Snort] 1:2000419");
    }

    @Test
    void ingest_darkEdgeAi_is200WithZeroAlerted_notAnError() {
        // inference.edge-ai.enabled=false (the default) → a `disabled` sentinel → no emit.
        when(service.triageAndNotify(anyString(), anyList(), anyString(), anyString()))
                .thenReturn(Mono.just(0L));

        web.post().uri(PATH).contentType(MediaType.APPLICATION_JSON).bodyValue(COLLECTOR_BODY)
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.accepted").isEqualTo(true)
                .jsonPath("$.alerted").isEqualTo(0);
    }

    @Test
    void ingest_blankDomain_is400_andNeverReachesTheService() {
        web.post().uri(PATH).contentType(MediaType.APPLICATION_JSON)
                .bodyValue(COLLECTOR_BODY.replace("\"domain\":\"brandx\"", "\"domain\":\"\""))
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).triageAndNotify(any(), any(), any(), any());
    }

    @Test
    void ingest_noRecipients_is400_andNeverReachesTheService() {
        web.post().uri(PATH).contentType(MediaType.APPLICATION_JSON)
                .bodyValue(COLLECTOR_BODY.replace(
                        "[\"google:admin1@example.org\",\"google:admin2@example.org\"]", "[]"))
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).triageAndNotify(any(), any(), any(), any());
    }

    @Test
    void ingest_blankRecipient_is400_andNeverReachesTheService() {
        web.post().uri(PATH).contentType(MediaType.APPLICATION_JSON)
                .bodyValue(COLLECTOR_BODY.replace("\"google:admin2@example.org\"", "\"\""))
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).triageAndNotify(any(), any(), any(), any());
    }

    @Test
    void ingest_blankEventKey_is400_andNeverReachesTheService() {
        web.post().uri(PATH).contentType(MediaType.APPLICATION_JSON)
                .bodyValue(COLLECTOR_BODY.replace(
                        "\"eventKey\":\"snort:rule-123:2026-08-20T12:00:00Z\"", "\"eventKey\":\"\""))
                .exchange().expectStatus().isBadRequest();
        verify(service, never()).triageAndNotify(any(), any(), any(), any());
    }
}
