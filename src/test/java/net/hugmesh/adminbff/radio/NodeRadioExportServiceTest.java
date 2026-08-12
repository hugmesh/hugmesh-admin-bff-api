package net.hugmesh.adminbff.radio;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.RegistrySigner;
import net.hugmesh.adminbff.radio.RadioExportModels.RadioEntry;
import net.hugmesh.adminbff.radio.RadioExportModels.SignedRadioExport;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The SIGNED PER-NODE node-radio export — REPRODUCES the storage-export acceptance bar
 * (confidentiality + signature + rollback) for the radio control plane. Two halves, both
 * pure-unit (no Spring, ephemeral key — NO signing key is ever committed):
 *
 * <h3>1. confidentiality + determinism (the per-node body)</h3>
 * the meshbridge agent fetches its OWN node's export and learns ONLY that node's radios —
 * never another node's; an unknown fp yields an EMPTY signed body (fail-closed, never a
 * leaky error, never an over-fetch of the radios repo); the canonical bytes are
 * reproducible; every per-transport column (serial path / host+port / topic root +
 * channel name + gateway id) rides the entry.
 *
 * <h3>2. the detached SIGNATURE + the consumer rollback guard</h3>
 * sign + verify round-trips; a consumer FAILS CLOSED on an UNSIGNED, TAMPERED, FOREIGN-KEY,
 * or ROLLED-BACK (generation &le; current) payload — keeping its last-good cache.
 */
class NodeRadioExportServiceTest {

    private final KeyPair keyPair = RegistrySigner.ephemeral();
    private final RegistrySigner signer = signerFrom(keyPair);

    /** Build a {@link RegistrySigner} via its PUBLIC base64 constructor (the package-private
     *  KeyPair ctor lives in the device package; this test is in radio). Encodes the
     *  ephemeral keypair to PKCS#8 / X.509 base64 — the SAME shape the deployment injects. */
    private static RegistrySigner signerFrom(KeyPair kp) {
        if (kp == null) return new RegistrySigner("", "", "");   // no-key (fail-closed)
        String priv = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        String pub = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        return new RegistrySigner(priv, "", pub);
    }

    private final DeviceRegistryRepository deviceRepo = mock(DeviceRegistryRepository.class);
    private final RadioDeviceRepository radioRepo = mock(RadioDeviceRepository.class);
    private final NodeRadioExportService service =
            new NodeRadioExportService(deviceRepo, radioRepo, signer);

    private static Device node(String id, String fp, String domain) {
        return new Device(id, fp, "host-" + id, "tn", Device.IMAGE_MESH_EXTENSION, "rpi5",
                Device.OWNER_ADMIN, "owner@" + domain, domain, "mesh-1", Instant.now(), null);
    }

    private static RadioDevice serialRadio(String id, String deviceId, String radioId, long gen) {
        return new RadioDevice(id, deviceId, RadioDevice.TRANSPORT_SERIAL, "/dev/ttyUSB0",
                null, null, null, null, null, radioId, 0, RadioDevice.STATE_ACTIVE, "brandx",
                RadioDevice.PROP_PENDING, gen, "op", Instant.now(), null, null);
    }

    private static RadioDevice mqttRadio(String id, String deviceId, String radioId, long gen) {
        return new RadioDevice(id, deviceId, RadioDevice.TRANSPORT_MQTT, null,
                "mqtt.example.org", 1883, "msh/US", "LongFast", "!0a1b2c3d", radioId, 3,
                RadioDevice.STATE_ACTIVE, "brandx", RadioDevice.PROP_PENDING, gen, "op",
                Instant.now(), null, null);
    }

    @Nested
    class ConfidentialityAndDeterminism {

        @Test
        void perNode_carriesOnlyThatNodesRadios_withAllTransportColumns() {
            Device nodeA = node("dev-a", "fp-a", "brandx");
            when(deviceRepo.findByMachineKey(eq("fp-a"))).thenReturn(Mono.just(nodeA));
            when(radioRepo.listActiveForDevice(eq("dev-a")))
                    .thenReturn(Flux.just(serialRadio("r1", "dev-a", "lora-0", 3L),
                                          mqttRadio("r2", "dev-a", "wan-0", 5L)));

            SignedRadioExport export = service.exportNode("fp-a").block();

            assertThat(export).isNotNull();
            assertThat(export.body().nodeFp()).isEqualTo("fp-a");
            assertThat(export.body().radios()).hasSize(2);
            RadioEntry serial = export.body().radios().stream()
                    .filter(r -> "lora-0".equals(r.radioId())).findFirst().orElseThrow();
            assertThat(serial.transport()).isEqualTo("serial");
            assertThat(serial.serialPath()).isEqualTo("/dev/ttyUSB0");
            assertThat(serial.host()).isNull();
            RadioEntry mqtt = export.body().radios().stream()
                    .filter(r -> "wan-0".equals(r.radioId())).findFirst().orElseThrow();
            assertThat(mqtt.transport()).isEqualTo("mqtt");
            assertThat(mqtt.host()).isEqualTo("mqtt.example.org");
            assertThat(mqtt.port()).isEqualTo(1883);
            assertThat(mqtt.topicRoot()).isEqualTo("msh/US");
            assertThat(mqtt.channelName()).isEqualTo("LongFast");
            assertThat(mqtt.gatewayNodeId()).isEqualTo("!0a1b2c3d");
            assertThat(mqtt.meshChannel()).isEqualTo(3);
            // generation is max across the node's radios (3, 5).
            assertThat(export.body().generation()).isEqualTo(5L);
        }

        @Test
        void perNode_unknownFingerprint_yieldsEmptySignedBody_notAnError_noOverFetch() {
            when(deviceRepo.findByMachineKey(eq("fp-ghost"))).thenReturn(Mono.empty());

            SignedRadioExport export = service.exportNode("fp-ghost").block();

            assertThat(export).isNotNull();
            assertThat(export.body().radios()).isEmpty();
            assertThat(export.body().nodeFp()).isEmpty();
            assertThat(export.signed()).isTrue();   // still signed over the empty body
            // the radios repo was NEVER read for an unknown node (no over-fetch, no
            // existence leak).
            verifyNoInteractions(radioRepo);
        }

        @Test
        void perNode_isReactiveAndFailClosed_completesWithASignedExport() {
            when(deviceRepo.findByMachineKey(eq("fp-x"))).thenReturn(Mono.empty());
            StepVerifier.create(service.exportNode("fp-x"))
                    .assertNext(e -> assertThat(e.signed()).isTrue())
                    .verifyComplete();
        }

        @Test
        void canonicalBytes_isDeterministic_regardlessOfRadioInputOrder() {
            Device n = node("dev-a", "fp-a", "brandx");
            when(deviceRepo.findByMachineKey(eq("fp-a"))).thenReturn(Mono.just(n));
            // two radios returned in REVERSE order on a second call.
            when(radioRepo.listActiveForDevice(eq("dev-a")))
                    .thenReturn(Flux.just(serialRadio("r2", "dev-a", "zoo", 1L),
                                          serialRadio("r1", "dev-a", "alpha", 1L)))
                    .thenReturn(Flux.just(serialRadio("r1", "dev-a", "alpha", 1L),
                                          serialRadio("r2", "dev-a", "zoo", 1L)));

            byte[] first = NodeRadioExportService.canonicalBytes(service.exportNode("fp-a").block().body());
            byte[] second = NodeRadioExportService.canonicalBytes(service.exportNode("fp-a").block().body());

            // stable sort by radioId -> reproducible canonical bytes + hash.
            assertThat(first).isEqualTo(second);
        }
    }

    @Nested
    class Signing {

        private SignedRadioExport signedSample(RegistrySigner s, long gen) {
            DeviceRegistryRepository dr = mock(DeviceRegistryRepository.class);
            RadioDeviceRepository rr = mock(RadioDeviceRepository.class);
            when(dr.findByMachineKey(eq("fp-a"))).thenReturn(Mono.just(node("dev-a", "fp-a", "brandx")));
            when(rr.listActiveForDevice(eq("dev-a")))
                    .thenReturn(Flux.just(mqttRadio("r1", "dev-a", "wan-0", gen)));
            return new NodeRadioExportService(dr, rr, s).exportNode("fp-a").block();
        }

        @Test
        void sign_thenVerify_roundTrips_withAdvertisedPublicKey() {
            SignedRadioExport export = signedSample(signer, 3L);

            assertThat(export.signed()).isTrue();
            byte[] canonical = NodeRadioExportService.canonicalBytes(export.body());
            assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey())).isTrue();
            assertThat(export.contentHash()).isEqualTo(RegistrySigner.contentHash(canonical));
        }

        @Test
        void verify_rejectsUnsigned_whenNoSigningKeyConfigured() {
            RegistrySigner noKey = signerFrom(null);
            SignedRadioExport export = signedSample(noKey, 1L);

            assertThat(export.signed()).isFalse();
            assertThat(export.signature()).isNull();
            byte[] canonical = NodeRadioExportService.canonicalBytes(export.body());
            assertThat(RegistrySigner.verify(canonical, export.signature(), export.publicKey())).isFalse();
        }

        @Test
        void verify_rejectsForeignKeySignature() {
            SignedRadioExport export = signedSample(signer, 1L);
            byte[] canonical = NodeRadioExportService.canonicalBytes(export.body());
            RegistrySigner rogue = signerFrom(RegistrySigner.ephemeral());
            String rogueSig = rogue.sign(canonical);
            assertThat(RegistrySigner.verify(canonical, rogueSig, export.publicKey())).isFalse();
        }

        @Test
        void verify_rejectsTamperedBody() {
            // Flipping the mqtt broker host after signing invalidates the signature — the
            // agent would otherwise be redirected to a rogue broker.
            SignedRadioExport export = signedSample(signer, 2L);
            RadioEntry real = export.body().radios().get(0);
            RadioEntry forged = new RadioEntry(real.radioId(), real.transport(), real.serialPath(),
                    "evil.example.org", real.port(), real.topicRoot(), real.channelName(),
                    real.gatewayNodeId(), real.meshChannel());
            var forgedBody = new RadioExportModels.RadioExportBody(
                    export.body().nodeFp(), export.body().generation(), java.util.List.of(forged));
            byte[] forgedBytes = NodeRadioExportService.canonicalBytes(forgedBody);
            assertThat(RegistrySigner.verify(forgedBytes, export.signature(), export.publicKey())).isFalse();
        }

        @Test
        void consumerRollbackGuard_rejectsLowerOrEqualGeneration_keepsLastGood() {
            SignedRadioExport gen5 = signedSample(signer, 5L);
            long lastGood = gen5.body().generation();        // agent caches gen 5

            SignedRadioExport gen3 = signedSample(signer, 3L);
            byte[] gen3Bytes = NodeRadioExportService.canonicalBytes(gen3.body());
            // validly signed...
            assertThat(RegistrySigner.verify(gen3Bytes, gen3.signature(), gen3.publicKey())).isTrue();
            // ...but the rollback guard rejects gen <= last-good.
            assertThat(gen3.body().generation() > lastGood).isFalse();
            assertThat(lastGood > lastGood).isFalse();        // equal -> reject
            assertThat((lastGood + 1) > lastGood).isTrue();   // strictly higher -> accept
        }
    }
}
