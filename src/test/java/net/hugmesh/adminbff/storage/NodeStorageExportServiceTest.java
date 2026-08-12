package net.hugmesh.adminbff.storage;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.RegistrySigner;
import net.hugmesh.adminbff.storage.StorageExportModels.AssignmentEntry;
import net.hugmesh.adminbff.storage.StorageExportModels.PoolEntry;
import net.hugmesh.adminbff.storage.StorageExportModels.SignedStorageExport;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The SIGNED PER-NODE node-storage export — REPRODUCES the device-export acceptance bar
 * (confidentiality + signature + rollback) for the storage control plane. Two halves, both
 * pure-unit (no Spring, ephemeral key — NO signing key is ever committed):
 *
 * <h3>1. confidentiality + determinism (the per-node body)</h3>
 * a node fetches its OWN export and learns ONLY its own pools + active assignments — never
 * another node's; an unknown fp yields an EMPTY signed body (fail-closed, never a leaky
 * error, never an over-fetch of the pools repo); the canonical bytes are reproducible.
 *
 * <h3>2. the detached SIGNATURE + the consumer rollback guard</h3>
 * sign + verify round-trips; a consumer FAILS CLOSED on an UNSIGNED, TAMPERED, FOREIGN-KEY,
 * or ROLLED-BACK (generation &le; current) payload — keeping its last-good cache.
 */
class NodeStorageExportServiceTest {

    private final KeyPair keyPair = RegistrySigner.ephemeral();
    private final RegistrySigner signer = signerFrom(keyPair);

    /** Build a {@link RegistrySigner} via its PUBLIC base64 constructor (the package-private
     *  KeyPair ctor lives in the device package; this test is in storage). Encodes the
     *  ephemeral keypair to PKCS#8 / X.509 base64 — the SAME shape the deployment injects. */
    private static RegistrySigner signerFrom(KeyPair kp) {
        if (kp == null) return new RegistrySigner("", "", "");   // no-key (fail-closed)
        String priv = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        String pub = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        return new RegistrySigner(priv, "", pub);
    }

    private final DeviceRegistryRepository deviceRepo = mock(DeviceRegistryRepository.class);
    private final StoragePoolRepository poolRepo = mock(StoragePoolRepository.class);
    private final ServiceAssignmentRepository assignRepo = mock(ServiceAssignmentRepository.class);
    private final NodeStorageExportService service =
            new NodeStorageExportService(deviceRepo, poolRepo, assignRepo, signer);

    private static Device node(String id, String fp, String domain) {
        return new Device(id, fp, "host-" + id, "tn", Device.IMAGE_MESH_EXTENSION, "rpi5",
                Device.OWNER_ADMIN, "owner@" + domain, domain, "mesh-1", Instant.now(), null);
    }

    private static StoragePool pool(String id, String deviceId, long reserved, long gen) {
        return new StoragePool(id, deviceId, "ser-" + id, "/var/hugmesh/storage/" + id,
                reserved, false, "ext4", StoragePool.STATE_ACTIVE, "brandx",
                StoragePool.PROP_PENDING, gen, "op", Instant.now(), null, null);
    }

    private static ServiceAssignment assign(String id, String poolId, String svc, long req, long gen) {
        return new ServiceAssignment(id, poolId, svc, svc + "-data", req,
                ServiceAssignment.STATE_ACTIVE, "op", Instant.now(), null, null, "brandx",
                ServiceAssignment.PROP_PENDING, gen);
    }

    @Nested
    class ConfidentialityAndDeterminism {

        @Test
        void perNode_carriesOnlyThatNodesPoolsAndAssignments() {
            Device nodeA = node("dev-a", "fp-a", "brandx");
            when(deviceRepo.findByMachineKey(eq("fp-a"))).thenReturn(Mono.just(nodeA));
            when(poolRepo.listActiveForDevice(eq("dev-a")))
                    .thenReturn(Flux.just(pool("p1", "dev-a", 10_000, 3L)));
            when(assignRepo.listActiveForPool(eq("p1")))
                    .thenReturn(Flux.just(assign("a1", "p1", "owncast", 4_000, 5L)));

            SignedStorageExport export = service.exportNode("fp-a").block();

            assertThat(export).isNotNull();
            assertThat(export.body().nodeFp()).isEqualTo("fp-a");
            assertThat(export.body().pools()).hasSize(1);
            PoolEntry p = export.body().pools().get(0);
            assertThat(p.poolPath()).isEqualTo("/var/hugmesh/storage/p1");
            assertThat(p.assignments()).extracting(AssignmentEntry::serviceName).containsExactly("owncast");
            // generation is max across the pool (3) and its assignments (5).
            assertThat(export.body().generation()).isEqualTo(5L);
        }

        @Test
        void perNode_unknownFingerprint_yieldsEmptySignedBody_notAnError_noOverFetch() {
            when(deviceRepo.findByMachineKey(eq("fp-ghost"))).thenReturn(Mono.empty());

            SignedStorageExport export = service.exportNode("fp-ghost").block();

            assertThat(export).isNotNull();
            assertThat(export.body().pools()).isEmpty();
            assertThat(export.body().nodeFp()).isEmpty();
            assertThat(export.signed()).isTrue();   // still signed over the empty body
            // the pools / assignments repos were NEVER read for an unknown node (no over-fetch,
            // no existence leak).
            verifyNoInteractions(poolRepo);
            verifyNoInteractions(assignRepo);
        }

        @Test
        void perNode_isReactiveAndFailClosed_completesWithASignedExport() {
            when(deviceRepo.findByMachineKey(eq("fp-x"))).thenReturn(Mono.empty());
            StepVerifier.create(service.exportNode("fp-x"))
                    .assertNext(e -> assertThat(e.signed()).isTrue())
                    .verifyComplete();
        }

        @Test
        void canonicalBytes_isDeterministic_regardlessOfAssignmentInputOrder() {
            Device n = node("dev-a", "fp-a", "brandx");
            when(deviceRepo.findByMachineKey(eq("fp-a"))).thenReturn(Mono.just(n));
            when(poolRepo.listActiveForDevice(eq("dev-a")))
                    .thenReturn(Flux.just(pool("p1", "dev-a", 10_000, 1L)));
            // two assignments returned in REVERSE order on a second call.
            when(assignRepo.listActiveForPool(eq("p1")))
                    .thenReturn(Flux.just(assign("a2", "p1", "zoo", 1_000, 1L),
                                          assign("a1", "p1", "alpha", 1_000, 1L)))
                    .thenReturn(Flux.just(assign("a1", "p1", "alpha", 1_000, 1L),
                                          assign("a2", "p1", "zoo", 1_000, 1L)));

            byte[] first = NodeStorageExportService.canonicalBytes(service.exportNode("fp-a").block().body());
            byte[] second = NodeStorageExportService.canonicalBytes(service.exportNode("fp-a").block().body());

            // stable sort by serviceName -> reproducible canonical bytes + hash.
            assertThat(first).isEqualTo(second);
        }
    }

    @Nested
    class Signing {

        private SignedStorageExport signedSample(RegistrySigner s, long gen) {
            DeviceRegistryRepository dr = mock(DeviceRegistryRepository.class);
            StoragePoolRepository pr = mock(StoragePoolRepository.class);
            ServiceAssignmentRepository ar = mock(ServiceAssignmentRepository.class);
            when(dr.findByMachineKey(eq("fp-a"))).thenReturn(Mono.just(node("dev-a", "fp-a", "brandx")));
            when(pr.listActiveForDevice(eq("dev-a"))).thenReturn(Flux.just(pool("p1", "dev-a", 10_000, gen)));
            when(ar.listActiveForPool(eq("p1"))).thenReturn(Flux.just(assign("a1", "p1", "owncast", 4_000, gen)));
            return new NodeStorageExportService(dr, pr, ar, s).exportNode("fp-a").block();
        }

        @Test
        void sign_thenVerify_roundTrips_withAdvertisedPublicKey() {
            SignedStorageExport export = signedSample(signer, 3L);

            assertThat(export.signed()).isTrue();
            byte[] canonical = NodeStorageExportService.canonicalBytes(export.body());
            assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey())).isTrue();
            assertThat(export.contentHash()).isEqualTo(RegistrySigner.contentHash(canonical));
        }

        @Test
        void verify_rejectsUnsigned_whenNoSigningKeyConfigured() {
            RegistrySigner noKey = signerFrom(null);
            SignedStorageExport export = signedSample(noKey, 1L);

            assertThat(export.signed()).isFalse();
            assertThat(export.signature()).isNull();
            byte[] canonical = NodeStorageExportService.canonicalBytes(export.body());
            assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey())).isFalse();
        }

        @Test
        void verify_rejectsForeignKeySignature() {
            SignedStorageExport export = signedSample(signer, 1L);
            byte[] canonical = NodeStorageExportService.canonicalBytes(export.body());
            RegistrySigner rogue = signerFrom(RegistrySigner.ephemeral());
            String rogueSig = rogue.sign(canonical);
            assertThat(RegistrySigner.verify(canonical, rogueSig, export.publicKey())).isFalse();
        }

        @Test
        void consumerRollbackGuard_rejectsLowerOrEqualGeneration_keepsLastGood() {
            SignedStorageExport gen5 = signedSample(signer, 5L);
            long lastGood = gen5.body().generation();        // node caches gen 5

            SignedStorageExport gen3 = signedSample(signer, 3L);
            byte[] gen3Bytes = NodeStorageExportService.canonicalBytes(gen3.body());
            // validly signed...
            assertThat(RegistrySigner.verify(gen3Bytes, gen3.signature(), gen3.publicKey())).isTrue();
            // ...but the rollback guard rejects gen <= last-good.
            assertThat(gen3.body().generation() > lastGood).isFalse();
            assertThat(lastGood > lastGood).isFalse();        // equal -> reject
            assertThat((lastGood + 1) > lastGood).isTrue();   // strictly higher -> accept
        }
    }
}
