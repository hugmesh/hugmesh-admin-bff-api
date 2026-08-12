package net.hugmesh.adminbff.inference;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.notification.FeatureNotificationService;
import net.hugmesh.adminbff.notification.FeatureNotificationService.Kind;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * AIOps triage→notify producer: a real edge-AI verdict fans out one INFRA_IMPACTING
 * notification per admin (delivered to Matrix @system DMs by the existing reconciler), while a
 * disabled/degraded edge-AI emits nothing (dark-by-default), and tenant/recipient are fail-closed.
 */
class AioTriageServiceTest {

    private final EdgeAiInferenceClient edgeAi = mock(EdgeAiInferenceClient.class);
    private final FeatureNotificationService notifications = mock(FeatureNotificationService.class);
    private final AioTriageService svc = new AioTriageService(edgeAi, notifications);

    @Test
    void availableVerdict_emitsOneInfraImpactingPerAdmin() {
        when(edgeAi.triageInfra(any()))
                .thenReturn(Mono.just(new TriageResult(true, "critical", "probable host compromise", "raw")));
        when(notifications.emit(eq(Kind.INFRA_IMPACTING), eq("brandx"), any(), any(), any()))
                .thenReturn(Mono.just(true));

        StepVerifier.create(svc.triageAndNotify("brandx",
                        List.of("google:admin1@x", "google:admin2@x"), "snort:rule-123", "[Snort] ..."))
                .expectNext(2L)
                .verifyComplete();

        // Neutral note carries the triage; each admin gets a distinct, idempotent event key.
        verify(notifications, times(2)).emit(eq(Kind.INFRA_IMPACTING), eq("brandx"),
                any(), any(), eq("CRITICAL — probable host compromise"));
    }

    @Test
    void disabledEdgeAi_emitsNothing() {
        when(edgeAi.triageInfra(any())).thenReturn(Mono.just(TriageResult.disabled()));

        StepVerifier.create(svc.triageAndNotify("brandx", List.of("google:admin1@x"), "k", "s"))
                .expectNext(0L)
                .verifyComplete();
        verify(notifications, never()).emit(any(), any(), any(), any(), any());
    }

    @Test
    void degradedEdgeAi_emitsNothing() {
        when(edgeAi.triageInfra(any())).thenReturn(Mono.just(TriageResult.degraded("TimeoutException")));

        StepVerifier.create(svc.triageAndNotify("brandx", List.of("google:admin1@x"), "k", "s"))
                .expectNext(0L)
                .verifyComplete();
        verify(notifications, never()).emit(any(), any(), any(), any(), any());
    }

    @Test
    void blankDomain_failsClosed() {
        StepVerifier.create(svc.triageAndNotify("", List.of("google:admin1@x"), "k", "s"))
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    void noRecipients_failsClosed() {
        StepVerifier.create(svc.triageAndNotify("brandx", List.of(), "k", "s"))
                .expectError(IllegalArgumentException.class)
                .verify();
    }
}
