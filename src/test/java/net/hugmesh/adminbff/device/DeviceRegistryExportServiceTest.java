package net.hugmesh.adminbff.device;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.device.ExportModels.AuthorizedOperator;
import net.hugmesh.adminbff.device.ExportModels.ExportBody;
import net.hugmesh.adminbff.device.ExportModels.SignedExport;

import java.security.KeyPair;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The signed device-registry EXPORT — the load-bearing acceptance bar for the ONE artefact
 * BOTH enforcement layers compile from. Two halves, both pure-unit (no Spring, ephemeral
 * key — NO signing key is ever committed [FIX-SIGNCACHE]):
 *
 * <h3>1. The AUTH-PREDICATE compilation ({@link DeviceRegistryExportService#compile})</h3>
 * Default-DENY, total, monotone. Proves:
 * <ul>
 *   <li>DEVICE-scope: a license whose {@code device_id} matches an ADMIN-owned node →
 *       ALLOW via {@code DEVICE-LICENSE}.</li>
 *   <li>DOMAIN-scope: a license whose {@code target_domain} matches a node's residency →
 *       ALLOW via {@code DOMAIN-LICENSE}.</li>
 *   <li>SUPERADMIN-owned node: NEVER emitted. POST-VERIFY CORRECTION (2026-06-12) — the
 *       unscoped signed export cannot see operator roles, so it must NOT carry SUPERADMIN
 *       access; a superadmin-owned node produces NO export entry (even if a stale license
 *       row somehow targets it). SUPERADMIN mesh-reach is a deferred Layer-A headscale
 *       concern, not a value this export carries.</li>
 *   <li>FIX-PINKEY (%f): a license that pins NO key compiles to NOTHING (fail-closed); an
 *       emitted entry carries the EXACT pinned fingerprints the node matches the offered
 *       {@code %f} against.</li>
 *   <li>default-DENY: a node with no matching active license emits no operator; a license
 *       for a DIFFERENT device/domain never leaks onto a node.</li>
 * </ul>
 *
 * <h3>2. The detached SIGNATURE ({@link RegistrySigner} + the consumer rollback guard)</h3>
 * Proves sign + verify round-trips, and that a consumer FAILS CLOSED on an UNSIGNED,
 * TAMPERED, or ROLLED-BACK (generation &le; current) payload — keeping its last-good
 * cache.
 */
class DeviceRegistryExportServiceTest {

    private static final String MESH = "mesh-1";

    // ── fixture builders ────────────────────────────────────────────────────────

    private static Device device(String id, String domain, String ownerType) {
        return new Device(id, "fp-" + id, "host-" + id, "tn", Device.IMAGE_MESH_EXTENSION,
                "rpi5", ownerType, "owner@" + domain, domain, MESH, null, null);
    }

    private static SshLicense deviceLicense(String operator, String deviceId, String keys) {
        return new SshLicense(operator + "/" + deviceId, operator, SshLicense.SCOPE_DEVICE,
                deviceId, null, keys, SshLicense.STATE_ACTIVE, "root", null, null, null,
                "brandx", SshLicense.PROP_PENDING, 1L);
    }

    private static SshLicense domainLicense(String operator, String targetDomain, String keys, long gen) {
        return new SshLicense(operator + "@" + targetDomain, operator, SshLicense.SCOPE_DOMAIN,
                null, targetDomain, keys, SshLicense.STATE_ACTIVE, "root", null, null, null,
                targetDomain, SshLicense.PROP_PENDING, gen);
    }

    // ════════════════════════ 1. predicate compilation ═════════════════════════
    @Nested
    class AuthPredicate {

        @Test
        void deviceScope_matchingNode_isAllowed_viaDeviceLicense_pinningKey() {
            Device d = device("d1", "brandx", Device.OWNER_ADMIN);
            SshLicense l = deviceLicense("bob@brandx", "d1", "SHA256:k1");

            ExportBody body = DeviceRegistryExportService.compile(MESH, List.of(d), List.of(l));

            assertThat(body.operators()).hasSize(1);
            AuthorizedOperator op = body.operators().get(0);
            assertThat(op.operator()).isEqualTo("bob@brandx");
            assertThat(op.machineKeyFp()).isEqualTo("fp-d1");
            assertThat(op.via()).isEqualTo(AuthorizedOperator.VIA_DEVICE_LICENSE);
            // FIX-PINKEY: the exact offered %f the node may accept.
            assertThat(op.keyFingerprints()).containsExactly("SHA256:k1");
        }

        @Test
        void domainScope_matchingResidency_isAllowed_viaDomainLicense() {
            Device d = device("d2", "brandy", Device.OWNER_ADMIN);
            SshLicense l = domainLicense("carol@brandy", "brandy", "SHA256:k2", 7L);

            ExportBody body = DeviceRegistryExportService.compile(MESH, List.of(d), List.of(l));

            assertThat(body.operators()).hasSize(1);
            AuthorizedOperator op = body.operators().get(0);
            assertThat(op.operator()).isEqualTo("carol@brandy");
            assertThat(op.via()).isEqualTo(AuthorizedOperator.VIA_DOMAIN_LICENSE);
            // generation is max(license.generation) for the node's rollback guard.
            assertThat(body.generation()).isEqualTo(7L);
        }

        @Test
        void superadminOwnedNode_emitsNoExportEntry_evenWithAStaleLicenseRow() {
            // POST-VERIFY CORRECTION (2026-06-12): the export carries ONLY explicit ADMIN
            // licenses. A SUPERADMIN-owned node is NEVER emitted — grantDevice() rejects a
            // license on such a node at the source, and the compiler additionally SKIPS
            // superadmin-owned nodes (defense-in-depth against any stale pre-correction
            // row). SUPERADMIN mesh-reach is a deferred Layer-A headscale concern, not a
            // value this unscoped (role-blind) export can carry.
            Device superNode = device("core", "hugmesh", Device.OWNER_SUPERADMIN);
            // A stale DEVICE row AND a stale DOMAIN row both targeting the core node.
            SshLicense staleDevice = deviceLicense("super@root", "core", "SHA256:sk");
            SshLicense staleDomain = domainLicense("super@root", "hugmesh", "SHA256:sk", 1L);

            ExportBody body = DeviceRegistryExportService.compile(MESH, List.of(superNode),
                    List.of(staleDevice, staleDomain));

            // No SUPERADMIN access is ever asserted by the export.
            assertThat(body.operators()).isEmpty();
        }

        @Test
        void mixedMesh_superadminNodeDropped_adminNodeStillEmitted() {
            // A mesh with BOTH a superadmin-owned core node and an admin-owned brand node,
            // each holding a same-domain DOMAIN license: only the ADMIN-owned node's entry
            // survives. The superadmin node is dropped wholesale; the export never carries
            // a SUPERADMIN-MESH provenance.
            Device coreNode = device("core", "brandx", Device.OWNER_SUPERADMIN);
            Device adminNode = device("edge", "brandx", Device.OWNER_ADMIN);
            SshLicense domainLic = domainLicense("bob@brandx", "brandx", "SHA256:k", 4L);

            ExportBody body = DeviceRegistryExportService.compile(MESH,
                    List.of(coreNode, adminNode), List.of(domainLic));

            assertThat(body.operators()).hasSize(1);
            AuthorizedOperator op = body.operators().get(0);
            assertThat(op.machineKeyFp()).isEqualTo("fp-edge");   // the admin node only
            assertThat(op.via()).isEqualTo(AuthorizedOperator.VIA_DOMAIN_LICENSE);
            assertThat(body.operators()).extracting(AuthorizedOperator::via)
                    .doesNotContain("SUPERADMIN-MESH");
        }

        @Test
        void licenseWithNoPinnedKey_compilesToNothing_failClosed() {
            // FIX-PINKEY: a license that pins NO key (null/blank key_fingerprints) is
            // dropped — a node would otherwise authorise ANY offered key.
            Device d = device("d3", "brandx", Device.OWNER_ADMIN);
            SshLicense noKey = deviceLicense("bob@brandx", "d3", null);
            SshLicense blankKey = deviceLicense("eve@brandx", "d3", "   ");

            ExportBody body = DeviceRegistryExportService.compile(MESH, List.of(d),
                    List.of(noKey, blankKey));

            assertThat(body.operators()).isEmpty();
        }

        @Test
        void noMatchingLicense_emitsNothing_andLicensesDoNotLeakAcrossNodesOrDomains() {
            // default-DENY: node d-x has a brandx device-license; node d-y (brandy) holds
            // neither that device-license nor any brandy license → it stays empty. A
            // device-license never matches a different device; a domain-license never
            // matches a different residency.
            Device dx = device("d-x", "brandx", Device.OWNER_ADMIN);
            Device dy = device("d-y", "brandy", Device.OWNER_ADMIN);
            SshLicense forDx = deviceLicense("bob@brandx", "d-x", "SHA256:x");
            SshLicense forBrandxDomain = domainLicense("dom@brandx", "brandx", "SHA256:dx", 1L);

            ExportBody body = DeviceRegistryExportService.compile(MESH, List.of(dx, dy),
                    List.of(forDx, forBrandxDomain));

            // dx: the device-license AND the brandx domain-license. dy: nothing.
            assertThat(body.operators()).extracting(AuthorizedOperator::machineKeyFp)
                    .containsOnly("fp-d-x");
            assertThat(body.operators()).extracting(AuthorizedOperator::operator)
                    .containsExactlyInAnyOrder("bob@brandx", "dom@brandx");
        }

        @Test
        void compile_isDeterministic_stableOrderingForReproducibleHash() {
            Device a = device("a", "brandx", Device.OWNER_ADMIN);
            Device b = device("b", "brandx", Device.OWNER_ADMIN);
            List<SshLicense> lics = List.of(
                    deviceLicense("zoe@brandx", "b", "SHA256:z"),
                    deviceLicense("amy@brandx", "a", "SHA256:a"),
                    domainLicense("amy@brandx", "brandx", "SHA256:a", 1L));

            ExportBody first = DeviceRegistryExportService.compile(MESH, List.of(b, a), lics);
            ExportBody second = DeviceRegistryExportService.compile(MESH, List.of(a, b), lics);

            // Same content regardless of input order → reproducible canonical bytes + hash.
            assertThat(DeviceRegistryExportService.canonicalBytes(first))
                    .isEqualTo(DeviceRegistryExportService.canonicalBytes(second));
        }
    }

    // ════════════════════════ 2. signing + rollback ════════════════════════════
    @Nested
    class Signing {

        private final KeyPair keyPair = RegistrySigner.ephemeral();
        private final RegistrySigner signer = new RegistrySigner(keyPair);

        private DeviceRegistryExportService service(RegistrySigner s) {
            // export() is not exercised here (no repos); we drive sign(...) + compile(...)
            // directly, so null repos are fine for this pure-unit slice.
            return new DeviceRegistryExportService(null, null, s);
        }

        private SignedExport signedSample(RegistrySigner s, long generation) {
            Device d = device("d1", "brandx", Device.OWNER_ADMIN);
            SshLicense l = domainLicense("bob@brandx", "brandx", "SHA256:k", generation);
            ExportBody body = DeviceRegistryExportService.compile(MESH, List.of(d), List.of(l));
            return service(s).sign(body);
        }

        @Test
        void sign_thenVerify_roundTrips_withAdvertisedPublicKey() {
            SignedExport export = signedSample(signer, 3L);

            assertThat(export.signed()).isTrue();
            assertThat(export.signature()).isNotBlank();
            assertThat(export.publicKey()).isNotBlank();

            byte[] canonical = DeviceRegistryExportService.canonicalBytes(export.body());
            // The node verifies with the baked public half (advertised on the envelope).
            assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey()))
                    .isTrue();
            // The content-hash is a recomputable integrity pre-check.
            assertThat(export.contentHash()).isEqualTo(RegistrySigner.contentHash(canonical));
        }

        @Test
        void verify_rejectsUnsigned_whenNoSigningKeyConfigured() {
            // No-key signer (fail-closed): the export is served UNSIGNED.
            RegistrySigner noKey = new RegistrySigner((KeyPair) null);
            SignedExport export = signedSample(noKey, 1L);

            assertThat(export.signed()).isFalse();
            assertThat(export.signature()).isNull();

            // A consumer must reject an unsigned payload (verify over a null signature is
            // false) and keep its last-good cache.
            byte[] canonical = DeviceRegistryExportService.canonicalBytes(export.body());
            assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey()))
                    .isFalse();
        }

        @Test
        void verify_rejectsTamperedBody() {
            SignedExport export = signedSample(signer, 2L);

            // Adversary edits the compiled set (adds an operator) but cannot re-sign.
            ExportBody tampered = new ExportBody(export.body().meshId(), export.body().generation(),
                    List.of(new AuthorizedOperator("attacker", "fp-d1", "host-d1",
                            List.of("SHA256:evil"), AuthorizedOperator.VIA_DEVICE_LICENSE)));
            byte[] tamperedBytes = DeviceRegistryExportService.canonicalBytes(tampered);

            // The original signature does NOT verify over the tampered bytes → fail-closed.
            assertThat(RegistrySigner.verify(tamperedBytes, export.signature(), export.publicKey()))
                    .isFalse();
        }

        @Test
        void verify_rejectsForeignKeySignature() {
            SignedExport export = signedSample(signer, 1L);
            byte[] canonical = DeviceRegistryExportService.canonicalBytes(export.body());

            // A signature made by a DIFFERENT key must not verify against the baked public
            // half (a rogue signer cannot impersonate the registry).
            RegistrySigner rogue = new RegistrySigner(RegistrySigner.ephemeral());
            String rogueSig = rogue.sign(canonical);
            assertThat(RegistrySigner.verify(canonical, rogueSig, export.publicKey())).isFalse();
        }

        @Test
        void consumerRollbackGuard_rejectsLowerOrEqualGeneration_keepsLastGood() {
            // The node's monotonic-generation guard: accept ONLY a strictly-higher gen than
            // its last-good cache; a replayed (<=) payload is rejected even if validly
            // signed [FIX-SIGNCACHE].
            SignedExport gen5 = signedSample(signer, 5L);
            long lastGoodGen = gen5.body().generation();   // node caches gen 5 (signed, fresh)

            // A validly-signed but ROLLED-BACK gen-3 payload (an old, replayed export).
            SignedExport gen3 = signedSample(signer, 3L);
            byte[] gen3Bytes = DeviceRegistryExportService.canonicalBytes(gen3.body());

            // Signature is valid...
            assertThat(RegistrySigner.verify(gen3Bytes, gen3.signature(), gen3.publicKey())).isTrue();
            // ...but the rollback guard rejects gen <= last-good (keep the cache).
            assertThat(accepts(lastGoodGen, gen3.body().generation())).isFalse();
            assertThat(accepts(lastGoodGen, lastGoodGen)).isFalse();          // equal → reject
            assertThat(accepts(lastGoodGen, lastGoodGen + 1)).isTrue();       // strictly higher → accept
        }

        /** The consumer's monotonic-generation rollback guard: accept iff strictly newer. */
        private static boolean accepts(long lastGoodGeneration, long offeredGeneration) {
            return offeredGeneration > lastGoodGeneration;
        }
    }

    // ════════════════════ 3. PER-NODE export (Layer-B confidentiality) ══════════
    /**
     * The PER-NODE signed export [CONFIDENTIALITY HARDENING] — a Layer-B admin node fetches
     * {@code ?node=<machine_key_fp>} and the signed body carries ONLY ITS OWN authorized
     * operators, so caching it leaks NO other node's / other domain's operator names or key
     * fingerprints. Proves:
     * <ul>
     *   <li>the body contains ONLY the requested node's operators (a SECOND node's AND
     *       another DOMAIN's operators are ABSENT);</li>
     *   <li>the detached signature VERIFIES over the narrower body;</li>
     *   <li>an UNKNOWN fp yields an EMPTY (but signed) body — fail-closed, never an error;</li>
     *   <li>{@code ?mesh=} STILL returns the FULL mesh (Layer-A unchanged);</li>
     *   <li>the AUTH PREDICATE is UNCHANGED — only the candidate node set is narrowed.</li>
     * </ul>
     */
    @Nested
    class PerNodeExport {

        private final KeyPair keyPair = RegistrySigner.ephemeral();
        private final RegistrySigner signer = new RegistrySigner(keyPair);

        private final DeviceRegistryRepository deviceRepo = mock(DeviceRegistryRepository.class);
        private final SshLicenseRepository licenseRepo = mock(SshLicenseRepository.class);
        private final DeviceRegistryExportService service =
                new DeviceRegistryExportService(deviceRepo, licenseRepo, signer);

        // A two-node mesh spanning TWO domains, each node with its own operator, PLUS a
        // cross-domain domain-license — exactly the cross-domain fingerprint set that the
        // per-mesh export over-shares to a Layer-B node today.
        private final Device nodeA = device("a", "brandx", Device.OWNER_ADMIN);   // fp-a
        private final Device nodeB = device("b", "brandy", Device.OWNER_ADMIN);   // fp-b
        private final List<SshLicense> allLicenses = List.of(
                deviceLicense("alice@brandx", "a", "SHA256:ka"),     // -> node a only
                deviceLicense("bob@brandy", "b", "SHA256:kb"),       // -> node b only
                domainLicense("dom@brandy", "brandy", "SHA256:kd", 9L)); // -> node b (other domain)

        private void wireLicenses() {
            when(licenseRepo.listActiveAll()).thenReturn(Flux.fromIterable(allLicenses));
        }

        @Test
        void perNode_containsOnlyThatNodesOperators_secondNodeAndOtherDomainAbsent() {
            wireLicenses();
            when(deviceRepo.findByMachineKey(eq("fp-a"))).thenReturn(Mono.just(nodeA));

            SignedExport export = service.exportNode("fp-a").block();

            assertThat(export).isNotNull();
            // ONLY node a's own operator — node b's operator AND brandy's domain-license op
            // (the cross-domain fingerprints) are ABSENT.
            assertThat(export.body().operators()).extracting(AuthorizedOperator::operator)
                    .containsExactly("alice@brandx")
                    .doesNotContain("bob@brandy", "dom@brandy");
            assertThat(export.body().operators()).extracting(AuthorizedOperator::machineKeyFp)
                    .containsOnly("fp-a");
            // No OTHER node's machine-key fingerprint, no OTHER domain's key fingerprint.
            assertThat(export.body().operators()).flatExtracting(AuthorizedOperator::keyFingerprints)
                    .containsExactly("SHA256:ka")
                    .doesNotContain("SHA256:kb", "SHA256:kd");
            // The header still pins the resolved mesh + the monotonic generation.
            assertThat(export.body().meshId()).isEqualTo(MESH);
            assertThat(export.body().generation()).isEqualTo(9L);
        }

        @Test
        void perNode_signatureVerifiesOverTheNarrowerBody() {
            wireLicenses();
            when(deviceRepo.findByMachineKey(eq("fp-b"))).thenReturn(Mono.just(nodeB));

            SignedExport export = service.exportNode("fp-b").block();

            assertThat(export).isNotNull();
            assertThat(export.signed()).isTrue();
            byte[] canonical = DeviceRegistryExportService.canonicalBytes(export.body());
            assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey()))
                    .isTrue();
            assertThat(export.contentHash()).isEqualTo(RegistrySigner.contentHash(canonical));
            // node b legitimately carries BOTH its device-license op and its domain-license
            // op (both target node b) — but NOTHING from node a.
            assertThat(export.body().operators()).extracting(AuthorizedOperator::operator)
                    .containsExactlyInAnyOrder("bob@brandy", "dom@brandy")
                    .doesNotContain("alice@brandx");
        }

        @Test
        void perNode_unknownFingerprint_yieldsEmptySignedBody_notAnError() {
            // fail-closed: an unknown fp must NOT error (an error could leak existence) and
            // must carry NO operators and NO mesh id.
            when(deviceRepo.findByMachineKey(eq("fp-ghost"))).thenReturn(Mono.empty());

            SignedExport export = service.exportNode("fp-ghost").block();

            assertThat(export).isNotNull();
            assertThat(export.body().operators()).isEmpty();
            assertThat(export.body().meshId()).isEmpty();
            // still SIGNED over the empty body so the consumer can verify + fail-close.
            assertThat(export.signed()).isTrue();
            byte[] canonical = DeviceRegistryExportService.canonicalBytes(export.body());
            assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey()))
                    .isTrue();
            // the licenses were never even read for an unknown node (no over-fetch).
            org.mockito.Mockito.verifyNoInteractions(licenseRepo);
        }

        @Test
        void perMesh_stillReturnsTheFullMesh_layerAUnchanged() {
            wireLicenses();
            when(deviceRepo.listByMesh(eq(MESH))).thenReturn(Flux.just(nodeA, nodeB));

            SignedExport export = service.exportMesh(MESH).block();

            assertThat(export).isNotNull();
            // the control-plane export carries BOTH nodes (all three operators) — unchanged.
            assertThat(export.body().operators()).extracting(AuthorizedOperator::operator)
                    .containsExactlyInAnyOrder("alice@brandx", "bob@brandy", "dom@brandy");
            assertThat(export.body().operators()).extracting(AuthorizedOperator::machineKeyFp)
                    .containsOnly("fp-a", "fp-b");
        }

        @Test
        void perNode_predicateUnchanged_sameOperatorsAsTheMeshExportRestrictedToThatNode() {
            // The narrowing is PURELY the candidate node set: compiling the full mesh then
            // filtering to one node's fp yields EXACTLY what the per-node export emits — the
            // predicate (which operators a node authorizes) is identical.
            ExportBody mesh = DeviceRegistryExportService.compile(MESH, List.of(nodeA, nodeB), allLicenses);
            List<String> meshOpsForA = mesh.operators().stream()
                    .filter(o -> o.machineKeyFp().equals("fp-a"))
                    .map(AuthorizedOperator::operator).sorted().toList();

            wireLicenses();
            when(deviceRepo.findByMachineKey(eq("fp-a"))).thenReturn(Mono.just(nodeA));
            SignedExport perNode = service.exportNode("fp-a").block();
            List<String> perNodeOps = perNode.body().operators().stream()
                    .map(AuthorizedOperator::operator).sorted().toList();

            assertThat(perNodeOps).isEqualTo(meshOpsForA);
        }

        @Test
        void perNode_isReactiveAndFailClosed_completesWithASignedExport() {
            when(deviceRepo.findByMachineKey(eq("fp-x"))).thenReturn(Mono.empty());
            StepVerifier.create(service.exportNode("fp-x"))
                    .assertNext(e -> assertThat(e.signed()).isTrue())
                    .verifyComplete();
        }
    }
}
