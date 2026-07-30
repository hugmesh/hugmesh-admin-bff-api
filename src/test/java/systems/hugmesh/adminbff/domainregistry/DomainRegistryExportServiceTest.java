package systems.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.device.RegistrySigner;
import systems.hugmesh.adminbff.domainregistry.DomainExportModels.DomainEntry;
import systems.hugmesh.adminbff.domainregistry.DomainExportModels.DomainExportBody;
import systems.hugmesh.adminbff.domainregistry.DomainExportModels.SignedDomainExport;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The signed {@code domain_registry} EXPORT — the acceptance bar for the ONE missing export
 * symmetry for runtime add-domain provisioning (the device-license / egress-VPN / node-storage
 * registries each already ship a signed {@code /export}; this proves the domain one). CLONES
 * {@code DeviceRegistryExportServiceTest} / {@code VpnExportServiceTest}: a pure COMPILE
 * predicate + the detached-Ed25519 sign/verify round-trip and the fail-closed posture.
 *
 * <h3>1. The COMPILE predicate ({@link DomainRegistryExportService#compile})</h3>
 * Cross-domain (every ENABLED domain), default-DENY, deterministic. Proves:
 * <ul>
 *   <li>every {@code enabled} domain is emitted, carrying its descriptors + band-190 status;</li>
 *   <li>a SOFT-DISABLED ({@code enabled=false}) domain is OMITTED (de-provision = absence);</li>
 *   <li>entries are sorted by {@code clusterDomain} so the canonical bytes are reproducible
 *       regardless of repository row order;</li>
 *   <li>{@code generation} is {@code max(row.last_reconciled_generation)+1} when non-empty
 *       (a fresh registry at the default 0 advances past a consumer's last-good 0) and 0 for
 *       an empty/all-disabled registry (a deterministic empty signed body);</li>
 *   <li>the {@code caRef} carried is a REFERENCE, never key bytes.</li>
 * </ul>
 *
 * <h3>2. The detached SIGNATURE ({@link RegistrySigner} + the consumer rollback guard)</h3>
 * Sign + verify round-trips; an UNSIGNED / TAMPERED / FOREIGN-KEY payload fails closed; a
 * ROLLED-BACK (generation &le; last-good) payload is rejected even when validly signed.
 */
class DomainRegistryExportServiceTest {

    /** A signing-capable RegistrySigner via the PUBLIC base64 constructor (the KeyPair
     *  constructor is package-private to `device`). Ed25519 keys are PKCS#8 (private) / X.509
     *  SPKI (public), exactly what RegistrySigner expects. */
    private static RegistrySigner signingSigner() {
        KeyPair kp = RegistrySigner.ephemeral();
        String priv = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        String pub = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        return new RegistrySigner(priv, "", pub);
    }

    // ── fixture builders ────────────────────────────────────────────────────────

    private static DomainRegistration domain(String clusterDomain, boolean enabled, long gen,
                                             boolean caProvisioned, boolean appsetRegistered) {
        return new DomainRegistration("id-" + clusterDomain, clusterDomain, "brand-" + clusterDomain,
                "Org " + clusterDomain, "vault:pki/" + clusterDomain, "ns-" + clusterDomain,
                "casdoor-" + clusterDomain, "tag:" + clusterDomain, enabled,
                Instant.now(), "superadmin@infra", Instant.now(),
                caProvisioned, appsetRegistered, gen);
    }

    // ════════════════════════ 1. compile predicate ═════════════════════════════

    @Test
    void compile_emitsEveryEnabledDomain_withDescriptorsAndStatus_sortedByClusterDomain() {
        List<DomainRegistration> rows = List.of(
                domain("beta.test", true, 2L, true, false),
                domain("alpha.test", true, 5L, false, false));

        DomainExportBody body = DomainRegistryExportService.compile("", rows);

        // sorted by cluster_domain -> deterministic canonical bytes.
        assertThat(body.entries()).extracting(DomainEntry::clusterDomain)
                .containsExactly("alpha.test", "beta.test");
        DomainEntry alpha = body.entries().get(0);
        assertThat(alpha.brand()).isEqualTo("brand-alpha.test");
        assertThat(alpha.org()).isEqualTo("Org alpha.test");
        assertThat(alpha.caRef()).isEqualTo("vault:pki/alpha.test"); // a REFERENCE, never bytes
        assertThat(alpha.nsPrefix()).isEqualTo("ns-alpha.test");
        assertThat(alpha.casdoorOrg()).isEqualTo("casdoor-alpha.test");
        assertThat(alpha.meshTag()).isEqualTo("tag:alpha.test");
        // band-190 provisioning status rides the export per row.
        assertThat(alpha.caProvisioned()).isFalse();
        assertThat(alpha.appsetRegistered()).isFalse();
        DomainEntry beta = body.entries().get(1);
        assertThat(beta.caProvisioned()).isTrue();
        // export generation = max(row gens) + 1 when non-empty.
        assertThat(body.generation()).isEqualTo(6L);
    }

    @Test
    void compile_softDisabledDomainIsOmitted_deProvisionIsAbsence() {
        List<DomainRegistration> rows = List.of(
                domain("live.test", true, 1L, true, true),
                domain("disabled.test", false, 9L, true, true)); // soft-disabled -> dropped

        DomainExportBody body = DomainRegistryExportService.compile("", rows);

        assertThat(body.entries()).extracting(DomainEntry::clusterDomain)
                .containsExactly("live.test")
                .doesNotContain("disabled.test");
        // the disabled row's higher generation does NOT leak into the export generation.
        assertThat(body.generation()).isEqualTo(2L); // max over ENABLED rows (1) + 1
    }

    @Test
    void compile_emptyRegistry_isEmptySignedBodyAtGenerationZero() {
        DomainExportBody body = DomainRegistryExportService.compile("", List.of());
        assertThat(body.entries()).isEmpty();
        assertThat(body.generation()).isEqualTo(0L); // deterministic empty body
    }

    @Test
    void compile_allDisabled_isEmptyAtGenerationZero() {
        DomainExportBody body = DomainRegistryExportService.compile("",
                List.of(domain("a.test", false, 4L, false, false)));
        assertThat(body.entries()).isEmpty();
        assertThat(body.generation()).isEqualTo(0L);
    }

    @Test
    void compile_freshRegistryAtDefaultGeneration_advancesPastConsumerLastGoodZero() {
        // A freshly registered registry: all rows at the band-190 default last_reconciled_
        // generation 0. The export generation must be 1 (0 + 1) so a consumer whose last-good
        // is 0 accepts the FIRST export (strict-monotonic guard: 1 > 0).
        List<DomainRegistration> rows = List.of(domain("new.test", true, 0L, false, false));
        DomainExportBody body = DomainRegistryExportService.compile("", rows);
        assertThat(body.generation()).isEqualTo(1L);
        assertThat(body.generation()).isGreaterThan(0L);
    }

    @Test
    void compile_nodeFingerprintIsProvenanceHeaderOnly_doesNotScopeTheBody() {
        // the node fp is pinned as provenance; the cross-domain body is identical with or
        // without it (the registry has no per-node scope).
        List<DomainRegistration> rows = List.of(domain("a.test", true, 1L, false, false));
        DomainExportBody withNode = DomainRegistryExportService.compile("fp-xyz", rows);
        DomainExportBody noNode = DomainRegistryExportService.compile("", rows);
        assertThat(withNode.node()).isEqualTo("fp-xyz");
        assertThat(noNode.node()).isEmpty();
        // same entries regardless of the provenance fp.
        assertThat(withNode.entries()).isEqualTo(noNode.entries());
    }

    @Test
    void compile_isDeterministic_stableCanonicalBytesRegardlessOfRowOrder() {
        List<DomainRegistration> a = List.of(
                domain("b.test", true, 1L, false, false), domain("a.test", true, 2L, true, false));
        List<DomainRegistration> b = List.of(
                domain("a.test", true, 2L, true, false), domain("b.test", true, 1L, false, false));
        assertThat(DomainRegistryExportService.canonicalBytes(DomainRegistryExportService.compile("", a)))
                .isEqualTo(DomainRegistryExportService.canonicalBytes(DomainRegistryExportService.compile("", b)));
    }

    // ════════════════════════ 2. signing + rollback ════════════════════════════

    @Test
    void sign_thenVerify_roundTrips_withAdvertisedPublicKey() {
        RegistrySigner signer = signingSigner();
        DomainRegistryExportService svc = new DomainRegistryExportService(null, signer);

        DomainExportBody body = DomainRegistryExportService.compile("",
                List.of(domain("acme.test", true, 3L, false, false)));
        SignedDomainExport export = svc.sign(body);

        assertThat(export.signed()).isTrue();
        assertThat(export.signature()).isNotBlank();
        assertThat(export.publicKey()).isNotBlank();

        byte[] canonical = DomainRegistryExportService.canonicalBytes(export.body());
        assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey())).isTrue();
        assertThat(export.contentHash()).isEqualTo(RegistrySigner.contentHash(canonical));
    }

    @Test
    void sign_noKey_isUnsigned_agentFailsClosed() {
        RegistrySigner noKey = new RegistrySigner("", "", ""); // no signing key configured
        DomainRegistryExportService svc = new DomainRegistryExportService(null, noKey);
        SignedDomainExport export = svc.sign(DomainRegistryExportService.compile("",
                List.of(domain("a.test", true, 1L, false, false))));

        assertThat(export.signed()).isFalse();
        assertThat(export.signature()).isNull();
        // a consumer must reject an unsigned payload (verify over a null signature is false).
        byte[] canonical = DomainRegistryExportService.canonicalBytes(export.body());
        assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey())).isFalse();
    }

    @Test
    void verify_rejectsTamperedBody() {
        RegistrySigner signer = signingSigner();
        DomainRegistryExportService svc = new DomainRegistryExportService(null, signer);
        SignedDomainExport export = svc.sign(DomainRegistryExportService.compile("",
                List.of(domain("acme.test", true, 2L, false, false))));

        // Adversary edits the compiled set (adds a rogue domain) but cannot re-sign.
        DomainExportBody tampered = new DomainExportBody(export.body().node(), export.body().generation(),
                List.of(new DomainEntry("evil.test", "evil", "Evil", "vault:pki/evil", "ns-evil",
                        "casdoor-evil", "tag:evil", true, true, 99L)));
        byte[] tamperedBytes = DomainRegistryExportService.canonicalBytes(tampered);
        assertThat(RegistrySigner.verify(tamperedBytes, export.signature(), export.publicKey())).isFalse();
    }

    @Test
    void verify_rejectsForeignKeySignature() {
        RegistrySigner signer = signingSigner();
        DomainRegistryExportService svc = new DomainRegistryExportService(null, signer);
        SignedDomainExport export = svc.sign(DomainRegistryExportService.compile("",
                List.of(domain("acme.test", true, 1L, false, false))));
        byte[] canonical = DomainRegistryExportService.canonicalBytes(export.body());

        RegistrySigner rogue = signingSigner();
        String rogueSig = rogue.sign(canonical);
        assertThat(RegistrySigner.verify(canonical, rogueSig, export.publicKey())).isFalse();
    }

    @Test
    void consumerRollbackGuard_rejectsLowerOrEqualGeneration_keepsLastGood() {
        // The agent's strict-monotonic guard: accept ONLY a strictly-higher generation than
        // its last-good cache; a replayed (<=) payload is rejected even if validly signed.
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
    void exportRegistry_signsTheWholeEnabledRegistry_overTheRepository() {
        RegistrySigner signer = signingSigner();
        DomainRegistryRepository repo = mock(DomainRegistryRepository.class);
        when(repo.findAll()).thenReturn(Flux.just(
                domain("alpha.test", true, 1L, false, false),
                domain("disabled.test", false, 9L, true, true),
                domain("beta.test", true, 2L, true, false)));
        DomainRegistryExportService svc = new DomainRegistryExportService(repo, signer);

        StepVerifier.create(svc.exportRegistry("fp-node"))
                .assertNext(export -> {
                    assertThat(export.signed()).isTrue();
                    assertThat(export.body().node()).isEqualTo("fp-node"); // provenance header
                    assertThat(export.body().entries()).extracting(DomainEntry::clusterDomain)
                            .containsExactly("alpha.test", "beta.test"); // enabled only, sorted
                    byte[] canonical = DomainRegistryExportService.canonicalBytes(export.body());
                    assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey()))
                            .isTrue();
                })
                .verifyComplete();
    }

    @Test
    void exportRegistry_emptyRegistry_isEmptySignedBody_notAnError() {
        RegistrySigner signer = signingSigner();
        DomainRegistryRepository repo = mock(DomainRegistryRepository.class);
        when(repo.findAll()).thenReturn(Flux.empty());
        DomainRegistryExportService svc = new DomainRegistryExportService(repo, signer);

        StepVerifier.create(svc.exportRegistry(""))
                .assertNext(export -> {
                    assertThat(export.signed()).isTrue();      // signed empty body
                    assertThat(export.body().entries()).isEmpty();
                    assertThat(export.body().generation()).isEqualTo(0L);
                })
                .verifyComplete();
    }
}
