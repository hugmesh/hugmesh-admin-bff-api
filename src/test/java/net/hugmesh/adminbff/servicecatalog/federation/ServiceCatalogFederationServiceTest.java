package net.hugmesh.adminbff.servicecatalog.federation;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.servicecatalog.FederateOutcome;
import net.hugmesh.adminbff.servicecatalog.ServiceDeployment;
import net.hugmesh.adminbff.web.dto.FederateServiceRequest;
import net.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The federate leg's business rules (Mockito unit): remoteEntryUrl structural validation,
 * kind/visibility defaults, metadata JSON assembly, the honest {@code federationReal}/
 * {@code gitopsDescriptorPending} outcome flags, and the status envelope.
 */
class ServiceCatalogFederationServiceTest {

    private final FederationModuleClient client = mock(FederationModuleClient.class);
    private final ServiceCatalogFederationService service = new ServiceCatalogFederationService(client);

    private static ServiceDeployment deployment() {
        return new ServiceDeployment("dep-1", "acme.test", "owncast", null,
                ServiceDeployment.STATE_ACTIVE, Instant.now(), null, null,
                ServiceDeployment.PROP_PENDING, null, "root");
    }

    private static FederateServiceRequest req(String remoteEntryUrl, String kind, String visibility) {
        return new FederateServiceRequest("owncast", "/owncast", "./routes", remoteEntryUrl,
                kind, visibility, "ROLE_OWNCAST");
    }

    @Test
    void federate_noopClient_registersWithDefaults_andReportsFederationRealFalse() {
        when(client.registerModule(any(), any(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(Mono.just("owncast"));
        when(client.isReal()).thenReturn(false);

        StepVerifier.create(service.federate(deployment(),
                        req("https://cdn.acme.test/owncast/remoteEntry.json", null, null)))
                .assertNext(outcome -> {
                    assertThat(outcome).isInstanceOf(FederateOutcome.class);
                    assertThat(outcome.federationReal()).isFalse();
                    // GitOps descriptor automation does not exist yet -> always pending.
                    assertThat(outcome.gitopsDescriptorPending()).isTrue();
                    assertThat(outcome.deployment().id()).isEqualTo("dep-1");
                })
                .verifyComplete();

        // Defaults applied: kind=remote-shell, visibility=internal, enabled=true; displayName is
        // the deployment's serviceKey; metadata carries mountAt + requiresRole as a JSON string.
        ArgumentCaptor<String> kind = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> visibility = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Boolean> enabled = ArgumentCaptor.forClass(Boolean.class);
        ArgumentCaptor<String> metadata = ArgumentCaptor.forClass(String.class);
        verify(client).registerModule(eq("owncast"), eq("owncast"), kind.capture(),
                eq("https://cdn.acme.test/owncast/remoteEntry.json"), eq("./routes"), eq(null),
                visibility.capture(), enabled.capture(), metadata.capture());
        assertThat(kind.getValue()).isEqualTo("remote-shell");
        assertThat(visibility.getValue()).isEqualTo("internal");
        assertThat(enabled.getValue()).isTrue();
        assertThat(metadata.getValue())
                .contains("\"mountAt\":\"/owncast\"")
                .contains("\"requiresRole\":\"ROLE_OWNCAST\"");
    }

    @Test
    void federate_realClient_reportsFederationRealTrue_andHonoursExplicitKindVisibility() {
        when(client.registerModule(any(), any(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(Mono.just("owncast"));
        when(client.isReal()).thenReturn(true);

        StepVerifier.create(service.federate(deployment(),
                        req("https://cdn.acme.test/owncast/remoteEntry.json", "fragment", "public")))
                .assertNext(outcome -> assertThat(outcome.federationReal()).isTrue())
                .verifyComplete();
        verify(client).registerModule(eq("owncast"), any(), eq("fragment"), any(), any(), eq(null),
                eq("public"), eq(true), any());
    }

    @Test
    void federate_invalidRemoteEntryUrl_400_neverRegisters() {
        // file: scheme is rejected by the repoUrl-style structural validator (SSRF/local-read guard).
        StepVerifier.create(service.federate(deployment(), req("file:///etc/passwd", null, null)))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.BAD_REQUEST);
                    assertThat(e.getMessage()).contains("remoteEntryUrl invalid");
                })
                .verify();
        verify(client, never()).registerModule(any(), any(), any(), any(), any(), any(), any(),
                anyBoolean(), any());
    }

    @Test
    void status_noop_enabledFalse_withWarning() {
        when(client.isReal()).thenReturn(false);
        var status = service.status();
        assertThat(status.get("enabled")).isEqualTo(false);
        assertThat((List<?>) status.get("warnings")).isNotEmpty();
    }

    @Test
    void status_real_enabledTrue_noWarnings() {
        when(client.isReal()).thenReturn(true);
        var status = service.status();
        assertThat(status.get("enabled")).isEqualTo(true);
        assertThat((List<?>) status.get("warnings")).isEmpty();
    }
}
