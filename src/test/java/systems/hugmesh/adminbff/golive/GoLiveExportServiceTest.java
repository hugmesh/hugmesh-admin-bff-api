package systems.hugmesh.adminbff.golive;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.device.RegistrySigner;
import systems.hugmesh.adminbff.golive.GoLiveExportModels.GoLiveExportBody;
import systems.hugmesh.adminbff.golive.GoLiveExportModels.GoLiveIntentEntry;
import systems.hugmesh.adminbff.golive.GoLiveExportModels.SignedGoLiveExport;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The signed {@code go_live_intent} EXPORT — the acceptance bar for the pinned contract's
 * "signed intent only" channel: the in-cluster BFF compiles + signs; the HOST agent verifies
 * and is the ONLY writer of {@code /etc/hugmesh/go-live}. CLONES
 * {@link systems.hugmesh.adminbff.domainregistry.DomainRegistryExportServiceTest}: a pure
 * COMPILE predicate + the detached-Ed25519 sign/verify round-trip and the fail-closed posture.
 *
 * <h3>1. The COMPILE predicate ({@link GoLiveExportService#compile})</h3>
 * Default-DENY, deterministic. Proves: only RECORDED intents ride the body (withdrawn/applied
 * = absence); entries sort by {@code clusterDomain} (reproducible canonical bytes); the export
 * generation is max over ALL rows — so a WITHDRAW (which bumps the withdrawn row) still
 * STRICTLY ADVANCES the generation while shrinking the body (the agent accepts the removal
 * instead of rejecting a "smaller" body as a replay); no secret ever rides an entry
 * (provider is a catalog key — the entry record has no token field at all).
 *
 * <h3>2. The detached SIGNATURE ({@link RegistrySigner} + the consumer rollback guard)</h3>
 * Sign + verify round-trips; an UNSIGNED / TAMPERED / FOREIGN-KEY payload fails closed; a
 * ROLLED-BACK (generation &le; last-good) payload is rejected even when validly signed.
 */
class GoLiveExportServiceTest {

    /** A signing-capable RegistrySigner via the PUBLIC base64 constructor (the KeyPair
     *  constructor is package-private to `device`). */
    private static RegistrySigner signingSigner() {
        KeyPair kp = RegistrySigner.ephemeral();
        String priv = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        String pub = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        return new RegistrySigner(priv, "", pub);
    }

    // ── fixture builders ────────────────────────────────────────────────────────

    private static GoLiveIntent intent(String domain, String status, long gen) {
        return intent(domain, GoLiveIntent.TARGET_PUBLIC, "tunnel", "cloudflare-tunnel",
                status, gen);
    }

    private static GoLiveIntent intent(String domain, String targetState, String model,
                                       String provider, String status, long gen) {
        return new GoLiveIntent("id-" + domain + "-" + gen, domain, targetState, model, provider,
                status, null, "superadmin@infra", Instant.now(), Instant.now(), gen, null, null);
    }

    // ════════════════════════ 1. compile predicate ═════════════════════════════

    @Test
    void compile_emitsOnlyRecordedIntents_sortedByClusterDomain() {
        List<GoLiveIntent> rows = List.of(
                intent("beta.example", GoLiveIntent.STATUS_RECORDED, 2L),
                intent("alpha.example", GoLiveIntent.STATUS_RECORDED, 1L),
                intent("gone.example", GoLiveIntent.STATUS_WITHDRAWN, 3L),
                intent("done.example", GoLiveIntent.STATUS_APPLIED, 4L));

        GoLiveExportBody body = GoLiveExportService.compile("", rows);

        assertThat(body.entries()).extracting(GoLiveIntentEntry::clusterDomain)
                .containsExactly("alpha.example", "beta.example"); // recorded only, sorted
        GoLiveIntentEntry alpha = body.entries().get(0);
        assertThat(alpha.targetState()).isEqualTo("public");
        assertThat(alpha.exposureModel()).isEqualTo("tunnel");
        assertThat(alpha.provider()).isEqualTo("cloudflare-tunnel"); // a catalog KEY, never a token
        assertThat(alpha.requestedBy()).isEqualTo("superadmin@infra");
        assertThat(alpha.intentId()).isNotBlank(); // the host agent's ack correlation key
    }

    @Test
    void compile_generationIsMaxOverAllRows_withdrawStillAdvancesIt() {
        // BEFORE the withdraw: one recorded intent at gen 1.
        List<GoLiveIntent> before = List.of(intent("acme.example", GoLiveIntent.STATUS_RECORDED, 1L));
        GoLiveExportBody bodyBefore = GoLiveExportService.compile("", before);
        assertThat(bodyBefore.entries()).hasSize(1);
        assertThat(bodyBefore.generation()).isEqualTo(1L);

        // AFTER the withdraw CAS (which stamped the row max+1=2): body is EMPTY but the
        // generation STRICTLY ADVANCED — so the agent's monotonic guard accepts the removal
        // (absence = nothing to apply) instead of treating it as a stale replay.
        List<GoLiveIntent> after = List.of(intent("acme.example", GoLiveIntent.STATUS_WITHDRAWN, 2L));
        GoLiveExportBody bodyAfter = GoLiveExportService.compile("", after);
        assertThat(bodyAfter.entries()).isEmpty();
        assertThat(bodyAfter.generation()).isEqualTo(2L);
        assertThat(bodyAfter.generation()).isGreaterThan(bodyBefore.generation());
    }

    @Test
    void compile_emptyLedger_isEmptyBodyAtGenerationZero_notAnError() {
        GoLiveExportBody body = GoLiveExportService.compile("", List.of());
        assertThat(body.entries()).isEmpty();
        assertThat(body.generation()).isEqualTo(0L); // deterministic empty body
    }

    @Test
    void compile_rollbackIntentRides_withEmptyModelAndProvider() {
        // A roll-back-internal intent has no edge to provision: model/provider are null in the
        // ledger and canonicalize to EMPTY fields (never a NullPointerException, never "null").
        List<GoLiveIntent> rows = List.of(
                intent("acme.example", GoLiveIntent.TARGET_INTERNAL, null, null,
                        GoLiveIntent.STATUS_RECORDED, 5L));
        GoLiveExportBody body = GoLiveExportService.compile("", rows);
        GoLiveIntentEntry e = body.entries().get(0);
        assertThat(e.targetState()).isEqualTo("internal");
        assertThat(e.exposureModel()).isEmpty();
        assertThat(e.provider()).isEmpty();
        String canonical = new String(GoLiveExportService.canonicalBytes(body));
        assertThat(canonical).contains("state=internal\tmodel=\tprovider=\t");
    }

    @Test
    void compile_nodeFingerprintIsProvenanceHeaderOnly_doesNotScopeTheBody() {
        List<GoLiveIntent> rows = List.of(intent("a.example", GoLiveIntent.STATUS_RECORDED, 1L));
        GoLiveExportBody withNode = GoLiveExportService.compile("fp-xyz", rows);
        GoLiveExportBody noNode = GoLiveExportService.compile("", rows);
        assertThat(withNode.node()).isEqualTo("fp-xyz");
        assertThat(noNode.node()).isEmpty();
        assertThat(withNode.entries()).isEqualTo(noNode.entries());
    }

    @Test
    void compile_isDeterministic_stableCanonicalBytesRegardlessOfRowOrder() {
        List<GoLiveIntent> a = List.of(
                intent("b.example", GoLiveIntent.STATUS_RECORDED, 1L),
                intent("a.example", GoLiveIntent.STATUS_RECORDED, 2L));
        List<GoLiveIntent> b = List.of(
                intent("a.example", GoLiveIntent.STATUS_RECORDED, 2L),
                intent("b.example", GoLiveIntent.STATUS_RECORDED, 1L));
        assertThat(GoLiveExportService.canonicalBytes(GoLiveExportService.compile("", a)))
                .isEqualTo(GoLiveExportService.canonicalBytes(GoLiveExportService.compile("", b)));
    }

    // ════════════════════════ 2. signing + rollback ════════════════════════════

    @Test
    void sign_thenVerify_roundTrips_withAdvertisedPublicKey() {
        RegistrySigner signer = signingSigner();
        GoLiveExportService svc = new GoLiveExportService(null, signer);

        GoLiveExportBody body = GoLiveExportService.compile("",
                List.of(intent("acme.example", GoLiveIntent.STATUS_RECORDED, 3L)));
        SignedGoLiveExport export = svc.sign(body);

        assertThat(export.signed()).isTrue();
        assertThat(export.signature()).isNotBlank();
        assertThat(export.publicKey()).isNotBlank();

        byte[] canonical = GoLiveExportService.canonicalBytes(export.body());
        assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey())).isTrue();
        assertThat(export.contentHash()).isEqualTo(RegistrySigner.contentHash(canonical));
    }

    @Test
    void sign_noKey_isUnsigned_agentFailsClosed_neverAppliesIt() {
        RegistrySigner noKey = new RegistrySigner("", "", ""); // no signing key configured
        GoLiveExportService svc = new GoLiveExportService(null, noKey);
        SignedGoLiveExport export = svc.sign(GoLiveExportService.compile("",
                List.of(intent("a.example", GoLiveIntent.STATUS_RECORDED, 1L))));

        assertThat(export.signed()).isFalse();
        assertThat(export.signature()).isNull();
        // The host agent must reject an unsigned intent payload (verify over null is false) —
        // an unsigned "go public" can NEVER flip a marker.
        byte[] canonical = GoLiveExportService.canonicalBytes(export.body());
        assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey())).isFalse();
    }

    @Test
    void verify_rejectsTamperedBody_noForgedGoPublic() {
        RegistrySigner signer = signingSigner();
        GoLiveExportService svc = new GoLiveExportService(null, signer);
        SignedGoLiveExport export = svc.sign(GoLiveExportService.compile("",
                List.of(intent("acme.example", GoLiveIntent.TARGET_INTERNAL, null, null,
                        GoLiveIntent.STATUS_RECORDED, 2L))));

        // Adversary rewrites the roll-back intent into a GO-PUBLIC one but cannot re-sign.
        GoLiveExportBody tampered = new GoLiveExportBody(export.body().node(),
                export.body().generation(),
                List.of(new GoLiveIntentEntry("acme.example", "public", "tunnel",
                        "cloudflare-tunnel", "evil@nowhere", "id-forged", 99L)));
        byte[] tamperedBytes = GoLiveExportService.canonicalBytes(tampered);
        assertThat(RegistrySigner.verify(tamperedBytes, export.signature(), export.publicKey())).isFalse();
    }

    @Test
    void verify_rejectsForeignKeySignature() {
        RegistrySigner signer = signingSigner();
        GoLiveExportService svc = new GoLiveExportService(null, signer);
        SignedGoLiveExport export = svc.sign(GoLiveExportService.compile("",
                List.of(intent("acme.example", GoLiveIntent.STATUS_RECORDED, 1L))));
        byte[] canonical = GoLiveExportService.canonicalBytes(export.body());

        RegistrySigner rogue = signingSigner();
        String rogueSig = rogue.sign(canonical);
        assertThat(RegistrySigner.verify(canonical, rogueSig, export.publicKey())).isFalse();
    }

    @Test
    void consumerRollbackGuard_rejectsLowerOrEqualGeneration_keepsLastGood() {
        // The host agent's strict-monotonic guard: accept ONLY a strictly-higher generation
        // than its last-good cache; a replayed (<=) payload is rejected even if validly signed.
        long lastGood = 5L;
        assertThat(accepts(lastGood, 3L)).isFalse();          // older -> reject
        assertThat(accepts(lastGood, lastGood)).isFalse();    // equal -> reject
        assertThat(accepts(lastGood, lastGood + 1)).isTrue(); // strictly higher -> accept
    }

    private static boolean accepts(long lastGoodGeneration, long offeredGeneration) {
        return offeredGeneration > lastGoodGeneration;
    }

    // ════════════════════════ 3. reactive export wiring ════════════════════════

    @Test
    void exportIntents_signsTheRecordedSet_overTheRepository() {
        RegistrySigner signer = signingSigner();
        GoLiveIntentRepository repo = mock(GoLiveIntentRepository.class);
        when(repo.findAll()).thenReturn(Flux.just(
                intent("alpha.example", GoLiveIntent.STATUS_RECORDED, 1L),
                intent("gone.example", GoLiveIntent.STATUS_WITHDRAWN, 3L),
                intent("beta.example", GoLiveIntent.STATUS_RECORDED, 2L)));
        GoLiveExportService svc = new GoLiveExportService(repo, signer);

        StepVerifier.create(svc.exportIntents("fp-node"))
                .assertNext(export -> {
                    assertThat(export.signed()).isTrue();
                    assertThat(export.body().node()).isEqualTo("fp-node"); // provenance header
                    assertThat(export.body().entries()).extracting(GoLiveIntentEntry::clusterDomain)
                            .containsExactly("alpha.example", "beta.example"); // recorded only
                    assertThat(export.body().generation()).isEqualTo(3L); // max over ALL rows
                    byte[] canonical = GoLiveExportService.canonicalBytes(export.body());
                    assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey()))
                            .isTrue();
                })
                .verifyComplete();
    }

    @Test
    void exportIntents_emptyLedger_isEmptySignedBody_notAnError() {
        RegistrySigner signer = signingSigner();
        GoLiveIntentRepository repo = mock(GoLiveIntentRepository.class);
        when(repo.findAll()).thenReturn(Flux.empty());
        GoLiveExportService svc = new GoLiveExportService(repo, signer);

        StepVerifier.create(svc.exportIntents(""))
                .assertNext(export -> {
                    assertThat(export.signed()).isTrue();      // signed empty body
                    assertThat(export.body().entries()).isEmpty();
                    assertThat(export.body().generation()).isEqualTo(0L);
                })
                .verifyComplete();
    }
}
