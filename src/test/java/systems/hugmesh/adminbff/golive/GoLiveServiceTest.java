package systems.hugmesh.adminbff.golive;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.golive.GoLiveProviderCatalog.GoLiveProvider;
import systems.hugmesh.adminbff.web.dto.RecordGoLiveIntentRequest;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * {@link GoLiveService} — the intent-ledger mechanism behind the wizard endpoints. Security
 * surface first (the controller test proves the HTTP gates; this proves the service refuses
 * BEFORE any write):
 * <ul>
 *   <li>SHIPS DARK: record/withdraw refuse with the dark exception BEFORE any repository
 *       interaction; the READS (history / provider catalog) stay live.</li>
 *   <li>VOCABULARY fail-closed: a bad targetState / missing exposureModel / unknown provider /
 *       provider-model mismatch / roll-back-with-provider is a clean 400-shaped refusal
 *       BEFORE any write.</li>
 *   <li>INTENT ONLY: the recorded row is {@code recorded} — the service has no code path that
 *       writes {@code applied} (that column is the host agent's, structurally).</li>
 *   <li>SUPERSEDE: at most one recorded intent per domain — a prior recorded intent is
 *       CAS-withdrawn (at the next monotonic generation) before the new insert.</li>
 *   <li>NO SECRETS: the provider catalog is public metadata only (https deep-links, input
 *       NAMES not values).</li>
 * </ul>
 */
class GoLiveServiceTest {

    private static final String ACTOR = "superadmin@infra";

    private final GoLiveIntentRepository repo = mock(GoLiveIntentRepository.class);

    private GoLiveService dark() {
        return new GoLiveService(false, repo);
    }

    private GoLiveService enabled() {
        return new GoLiveService(true, repo);
    }

    private static RecordGoLiveIntentRequest goPublic() {
        return new RecordGoLiveIntentRequest("acme.example", "public", "tunnel",
                "cloudflare-tunnel", null);
    }

    private static GoLiveIntent recorded(String id, String domain, long gen) {
        return new GoLiveIntent(id, domain, "public", "tunnel", "cloudflare-tunnel",
                GoLiveIntent.STATUS_RECORDED, null, ACTOR, Instant.now(), Instant.now(), gen,
                null, null);
    }

    // ── ships dark ──────────────────────────────────────────────────────────────────

    @Test
    void record_dark_refusesBeforeAnyWrite() {
        StepVerifier.create(dark().record(ACTOR, goPublic()))
                .expectError(GoLiveService.GoLiveDarkException.class)
                .verify();
        verifyNoInteractions(repo); // dark refusal is EARLY — nothing touched the ledger
    }

    @Test
    void withdraw_dark_refusesBeforeAnyWrite() {
        StepVerifier.create(dark().withdraw(ACTOR, "gl-1"))
                .expectError(GoLiveService.GoLiveDarkException.class)
                .verify();
        verifyNoInteractions(repo);
    }

    @Test
    void reads_stayLiveWhileDark_theWizardRendersHonestly() {
        when(repo.findAll()).thenReturn(Flux.just(recorded("gl-1", "acme.example", 1L)));
        GoLiveService svc = dark();
        assertThat(svc.isEnabled()).isFalse();
        StepVerifier.create(svc.history()).expectNextCount(1).verifyComplete();
        assertThat(svc.providers()).isNotEmpty();
    }

    // ── vocabulary fail-closed (before any write) ───────────────────────────────────

    @Test
    void record_badTargetState_refuses() {
        StepVerifier.create(enabled().record(ACTOR,
                        new RecordGoLiveIntentRequest("acme.example", "live", null, null, null)))
                .expectError(GoLiveService.GoLiveValidationException.class)
                .verify();
        verifyNoInteractions(repo);
    }

    @Test
    void record_publicWithoutExposureModel_refuses() {
        StepVerifier.create(enabled().record(ACTOR,
                        new RecordGoLiveIntentRequest("acme.example", "public", null,
                                "cloudflare-tunnel", null)))
                .expectError(GoLiveService.GoLiveValidationException.class)
                .verify();
        verifyNoInteractions(repo);
    }

    @Test
    void record_unknownProvider_refuses() {
        StepVerifier.create(enabled().record(ACTOR,
                        new RecordGoLiveIntentRequest("acme.example", "public", "tunnel",
                                "not-a-provider", null)))
                .expectError(GoLiveService.GoLiveValidationException.class)
                .verify();
        verifyNoInteractions(repo);
    }

    @Test
    void record_providerModelMismatch_refuses() {
        // duckdns serves public_dns, not tunnel — the catalog is the vocabulary.
        StepVerifier.create(enabled().record(ACTOR,
                        new RecordGoLiveIntentRequest("acme.example", "public", "tunnel",
                                "duckdns", null)))
                .expectError(GoLiveService.GoLiveValidationException.class)
                .verify();
        verifyNoInteractions(repo);
    }

    @Test
    void record_rollbackWithProvider_refuses() {
        // A roll-back-internal intent has no edge to provision.
        StepVerifier.create(enabled().record(ACTOR,
                        new RecordGoLiveIntentRequest("acme.example", "internal", "tunnel",
                                "cloudflare-tunnel", null)))
                .expectError(GoLiveService.GoLiveValidationException.class)
                .verify();
        verifyNoInteractions(repo);
    }

    // ── record: happy path + supersede + monotonic generation ───────────────────────

    @Test
    void record_insertsRecordedIntent_atNextMonotonicGeneration() {
        when(repo.findRecordedForDomain("acme.example")).thenReturn(Flux.empty());
        when(repo.maxGeneration()).thenReturn(Mono.just(4L));
        GoLiveIntent persisted = recorded("gl-new", "acme.example", 5L);
        when(repo.insertRecorded(eq("acme.example"), eq("public"), eq("tunnel"),
                eq("cloudflare-tunnel"), any(), eq(ACTOR), eq(5L)))
                .thenReturn(Mono.just(persisted));

        StepVerifier.create(enabled().record(ACTOR, goPublic()))
                .assertNext(i -> {
                    assertThat(i.status()).isEqualTo(GoLiveIntent.STATUS_RECORDED);
                    // INTENT ONLY: never applied by the BFF; the ack surface stays empty.
                    assertThat(i.toMap()).containsEntry("applied", false);
                    assertThat(i.appliedAt()).isNull();
                    assertThat(i.generation()).isEqualTo(5L);
                })
                .verifyComplete();
        verify(repo, never()).withdraw(anyString(), anyLong()); // nothing to supersede
    }

    @Test
    void record_supersedesThePriorRecordedIntentForTheSameDomain() {
        // One prior recorded intent exists -> it is CAS-withdrawn (gen 5) BEFORE the new
        // insert (gen 6): at most one recorded intent per domain, generations strictly climb.
        when(repo.findRecordedForDomain("acme.example"))
                .thenReturn(Flux.just(recorded("gl-old", "acme.example", 2L)));
        when(repo.maxGeneration()).thenReturn(Mono.just(4L), Mono.just(5L));
        when(repo.withdraw("gl-old", 5L)).thenReturn(Mono.just(1L));
        when(repo.insertRecorded(eq("acme.example"), eq("public"), eq("tunnel"),
                eq("cloudflare-tunnel"), any(), eq(ACTOR), eq(6L)))
                .thenReturn(Mono.just(recorded("gl-new", "acme.example", 6L)));

        StepVerifier.create(enabled().record(ACTOR, goPublic()))
                .assertNext(i -> assertThat(i.id()).isEqualTo("gl-new"))
                .verifyComplete();
        verify(repo).withdraw("gl-old", 5L);
    }

    @Test
    void record_normalizesVocabularyToLowercase() {
        when(repo.findRecordedForDomain("acme.example")).thenReturn(Flux.empty());
        when(repo.maxGeneration()).thenReturn(Mono.just(0L));
        when(repo.insertRecorded(eq("acme.example"), eq("public"), eq("tunnel"),
                eq("cloudflare-tunnel"), any(), eq(ACTOR), eq(1L)))
                .thenReturn(Mono.just(recorded("gl-1", "acme.example", 1L)));

        StepVerifier.create(enabled().record(ACTOR,
                        new RecordGoLiveIntentRequest("  ACME.Example ", "PUBLIC", "Tunnel",
                                "Cloudflare-Tunnel", null)))
                .expectNextCount(1)
                .verifyComplete();
        // The eq() stubs above ARE the assertion: canonical-lowercase reached the ledger.
        verify(repo).insertRecorded(eq("acme.example"), eq("public"), eq("tunnel"),
                eq("cloudflare-tunnel"), any(), eq(ACTOR), eq(1L));
    }

    @Test
    void record_rollbackInternal_needsNoProvider() {
        when(repo.findRecordedForDomain("acme.example")).thenReturn(Flux.empty());
        when(repo.maxGeneration()).thenReturn(Mono.just(7L));
        when(repo.insertRecorded(eq("acme.example"), eq("internal"), eq(null), eq(null),
                any(), eq(ACTOR), eq(8L)))
                .thenReturn(Mono.just(new GoLiveIntent("gl-rb", "acme.example", "internal",
                        null, null, GoLiveIntent.STATUS_RECORDED, null, ACTOR, Instant.now(),
                        Instant.now(), 8L, null, null)));

        StepVerifier.create(enabled().record(ACTOR,
                        new RecordGoLiveIntentRequest("acme.example", "internal", null, null, null)))
                .assertNext(i -> assertThat(i.targetState()).isEqualTo("internal"))
                .verifyComplete();
    }

    // ── withdraw ────────────────────────────────────────────────────────────────────

    @Test
    void withdraw_casAtNextMonotonicGeneration_reportsRowsUpdated() {
        when(repo.maxGeneration()).thenReturn(Mono.just(9L));
        when(repo.withdraw("gl-1", 10L)).thenReturn(Mono.just(1L));
        StepVerifier.create(enabled().withdraw(ACTOR, "gl-1"))
                .expectNext(1L)
                .verifyComplete();
    }

    @Test
    void withdraw_absentOrAlreadyTerminal_reportsZero() {
        when(repo.maxGeneration()).thenReturn(Mono.just(9L));
        when(repo.withdraw("gl-x", 10L)).thenReturn(Mono.just(0L));
        StepVerifier.create(enabled().withdraw(ACTOR, "gl-x"))
                .expectNext(0L)
                .verifyComplete();
    }

    // ── applied-ack (host-agent surface; NOT dark-gated) ─────────────────────────────

    @Test
    void applyAck_delegatesTheRowsOwnGeneration_toTheRepositoryCas() {
        // The service must pass through the CALLER's generation (the intent's own per-row
        // stamp) verbatim — it must never substitute maxGeneration() / any "latest export
        // generation" notion here (that would break the CAS-supersede safety property).
        when(repo.markApplied("gl-1", 7L, "node-fp-abc")).thenReturn(Mono.just(1L));
        StepVerifier.create(enabled().applyAck("gl-1", 7L, "node-fp-abc"))
                .expectNext(1L)
                .verifyComplete();
        verify(repo).markApplied("gl-1", 7L, "node-fp-abc");
        verify(repo, never()).maxGeneration(); // no monotonic-floor read on this path
    }

    @Test
    void applyAck_casLoss_reportsZero_notAnError() {
        // Already applied / withdrawn / superseded (stale generation, different id) — a
        // normal idempotent no-op for a retrying host agent, never an exception.
        when(repo.markApplied("gl-1", 7L, "node-fp-abc")).thenReturn(Mono.just(0L));
        StepVerifier.create(enabled().applyAck("gl-1", 7L, "node-fp-abc"))
                .expectNext(0L)
                .verifyComplete();
    }

    @Test
    void applyAck_notDarkGated_worksEvenWhileDark() {
        // Deliberately NOT gated by app.go-live.enabled: a row can only be 'recorded' while
        // the wizard was enabled in the first place, and finishing an in-flight ack after a
        // later dark-toggle is correctness-positive, not a hazard (mirrors
        // ImageBuildIngestController.ingest, also un-gated by any feature flag).
        when(repo.markApplied("gl-1", 1L, "node-fp")).thenReturn(Mono.just(1L));
        StepVerifier.create(dark().applyAck("gl-1", 1L, "node-fp"))
                .expectNext(1L)
                .verifyComplete();
    }

    // ── provider catalog (public metadata only) ─────────────────────────────────────

    @Test
    void catalog_carriesTheDesignsPrioritizedProviders_flagshipFirst() {
        assertThat(GoLiveProviderCatalog.PROVIDERS).extracting(GoLiveProvider::key)
                .containsExactly("cloudflare-tunnel", "byo-domain", "duckdns",
                        "cloudflare-ddns", "tailscale-funnel", "router-portforward");
        // The v1 API/deep-link split: only the DDNS single-token updaters are real drivers.
        assertThat(GoLiveProviderCatalog.PROVIDERS.stream()
                .filter(GoLiveProvider::apiDriver).map(GoLiveProvider::key))
                .containsExactly("duckdns", "cloudflare-ddns");
    }

    @Test
    void catalog_deepLinksAreHttps_andInputsAreNamesNotValues() {
        for (GoLiveProvider p : GoLiveProviderCatalog.PROVIDERS) {
            assertThat(p.deepLink()).startsWith("https://");
            // Input NAMES only — a catalog row structurally cannot carry a token value.
            for (String input : p.requiredInputs()) {
                assertThat(input).doesNotContainAnyWhitespaces();
            }
            assertThat(p.exposureModel()).isIn(GoLiveProviderCatalog.MODEL_TUNNEL,
                    GoLiveProviderCatalog.MODEL_PUBLIC_DNS, GoLiveProviderCatalog.MODEL_FUNNEL);
        }
    }

    @Test
    void catalog_findIsKeyExact_missingIsEmpty() {
        assertThat(GoLiveProviderCatalog.find("cloudflare-tunnel")).isPresent();
        assertThat(GoLiveProviderCatalog.find("Cloudflare-Tunnel")).isEmpty(); // exact-match
        assertThat(GoLiveProviderCatalog.find(null)).isEmpty();
    }
}
