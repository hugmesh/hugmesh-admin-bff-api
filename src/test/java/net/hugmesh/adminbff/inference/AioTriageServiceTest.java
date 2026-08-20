package net.hugmesh.adminbff.inference;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.notification.FeatureNotificationService;
import net.hugmesh.adminbff.notification.FeatureNotificationService.Kind;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
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
 * Plus the per-admin outbox key contract: it must FIT {@code notification_outbox.source_id}
 * ({@code varchar(36)}), stay stable per (eventKey, admin) and stay distinct across admins.
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
    void perAdminOutboxKey_fitsTheSourceIdColumn_stablePerAdmin_distinctAcrossAdmins() {
        // The literal "eventKey:admin" pair this service used to pass is 61 characters here —
        // over the varchar(36) source_id, where the INSERT either fails outright or (when the
        // driver reports the overflow as a data-integrity violation) is swallowed by
        // insertIfAbsent's duplicate classifier and the alert vanishes, reported as 0 alerted.
        String eventKey = "snort:rule-123:2026-08-20T12:00:00Z";
        String admin1 = "google:admin1@example.org";
        String admin2 = "google:admin2@example.org";
        when(edgeAi.triageInfra(any()))
                .thenReturn(Mono.just(new TriageResult(true, "critical", "probable host compromise", "raw")));
        when(notifications.emit(eq(Kind.INFRA_IMPACTING), eq("brandx"), any(), any(), any()))
                .thenReturn(Mono.just(true));

        StepVerifier.create(svc.triageAndNotify("brandx", List.of(admin1, admin2),
                        eventKey, "[Snort] ..."))
                .expectNext(2L)
                .verifyComplete();

        // FITS: every derived key is exactly the width of notification_outbox.source_id.
        ArgumentCaptor<String> keys = ArgumentCaptor.forClass(String.class);
        verify(notifications, times(2)).emit(eq(Kind.INFRA_IMPACTING), eq("brandx"),
                any(), keys.capture(), any());
        assertThat(keys.getAllValues()).allSatisfy(k -> assertThat(k).hasSize(36))
                .doesNotHaveDuplicates();   // DISTINCT: the per-recipient fan-out survives.

        // STABLE: replaying the same batch re-derives admin1's key byte-for-byte — what makes
        // the outbox UNIQUE(source_table, source_id, category) dedup a retried signal.
        StepVerifier.create(svc.triageAndNotify("brandx", List.of(admin1), eventKey, "[Snort] ..."))
                .expectNext(1L)
                .verifyComplete();
        ArgumentCaptor<String> admin1Keys = ArgumentCaptor.forClass(String.class);
        verify(notifications, times(2)).emit(eq(Kind.INFRA_IMPACTING), eq("brandx"),
                eq(admin1), admin1Keys.capture(), any());
        assertThat(admin1Keys.getAllValues().get(1)).isEqualTo(admin1Keys.getAllValues().get(0));
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
