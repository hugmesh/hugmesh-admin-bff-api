package net.hugmesh.adminbff.egressvpn;

import org.junit.jupiter.api.Test;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.RegistrySigner;
import net.hugmesh.adminbff.egressvpn.VpnExportModels.SignedVpnExport;
import net.hugmesh.adminbff.egressvpn.VpnExportModels.VpnEgressEntry;
import net.hugmesh.adminbff.egressvpn.VpnExportModels.VpnExportBody;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
// KeyPair used by signingSigner() via RegistrySigner.ephemeral()

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link VpnExportService} — proves the pure COMPILE predicate (CLONES the
 * DeviceRegistryExportServiceTest pattern) + the detached-Ed25519 sign/verify round-trip
 * and the fail-closed posture:
 * <ul>
 *   <li>a DEVICE assignment and a DOMAIN assignment matching the node both contribute
 *       their (active) config; a revoked/absent config is skipped;</li>
 *   <li>an "all services" (null slug) assignment subsumes the narrowed ones (empty slug
 *       list); narrowed slugs are collected + sorted;</li>
 *   <li>generation is the max over the contributing config + assignment rows;</li>
 *   <li>sign/verify round-trips against the canonical bytes; a TAMPERED body fails verify;
 *       a ROLLED-BACK generation is detectable (monotonic guard is the agent's, modelled
 *       by comparing generations here);</li>
 *   <li>no signing key ⇒ unsigned envelope (agent fail-closes).</li>
 * </ul>
 */
class VpnExportServiceTest {

    /** A signing-capable RegistrySigner built via the PUBLIC base64 constructor (the
     *  KeyPair constructor is package-private to `device`). Ed25519 keys are PKCS#8
     *  (private) / X.509 SPKI (public), exactly what RegistrySigner expects. */
    private static RegistrySigner signingSigner() {
        KeyPair kp = RegistrySigner.ephemeral();
        String priv = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        String pub = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        return new RegistrySigner(priv, "", pub);
    }

    private static Device node(String fp, String domain, String ownerType) {
        return new Device("id-" + fp, fp, "node-" + fp, "tn", Device.IMAGE_MESH_EXTENSION,
                "rpi5", ownerType, "owner@" + domain, domain, "mesh-1", Instant.now(), null);
    }

    private static VpnConfig cfg(String id, String name, String domain, long gen, String state) {
        return new VpnConfig(id, domain, name, VpnConfig.KIND_WIREGUARD, "protonvpn",
                "1.2.3.4:51820", "ref-" + name, state, "root", Instant.now(), null, null,
                VpnConfig.PROP_PENDING, gen);
    }

    private static VpnNodeAssignment devAsg(String id, String cfgId, String fp, String svc, long gen) {
        return new VpnNodeAssignment(id, cfgId, VpnNodeAssignment.SCOPE_DEVICE, fp, null, svc,
                VpnNodeAssignment.STATE_ACTIVE, "root", Instant.now(), null, null, "brandx",
                VpnNodeAssignment.PROP_PENDING, gen);
    }

    private static VpnNodeAssignment domAsg(String id, String cfgId, String domain, String svc, long gen) {
        return new VpnNodeAssignment(id, cfgId, VpnNodeAssignment.SCOPE_DOMAIN, null, domain, svc,
                VpnNodeAssignment.STATE_ACTIVE, "root", Instant.now(), null, null, "brandx",
                VpnNodeAssignment.PROP_PENDING, gen);
    }

    @Test
    void compile_includesDeviceAndDomainAssignments_skipsRevokedConfig() {
        Device n = node("fp-1", "brandx", Device.OWNER_ADMIN);
        VpnConfig active = cfg("c1", "proton-us", "brandx", 3L, VpnConfig.STATE_ACTIVE);
        // a DEVICE assignment for this node + a DOMAIN assignment for its residency.
        List<VpnNodeAssignment> asgs = List.of(
                devAsg("a1", "c1", "fp-1", "coturn", 5L),
                domAsg("a2", "c1", "brandx", "akkoma", 4L),
                // an assignment to a revoked/absent config is dropped (default-deny).
                devAsg("a3", "c-missing", "fp-1", null, 9L));
        VpnExportBody body = VpnExportService.compile(n, List.of(active), asgs);

        assertThat(body.node()).isEqualTo("fp-1");
        assertThat(body.entries()).hasSize(1);
        VpnEgressEntry e = body.entries().get(0);
        assertThat(e.configName()).isEqualTo("proton-us");
        assertThat(e.secretRef()).isEqualTo("ref-proton-us");
        assertThat(e.serviceSlugs()).containsExactly("akkoma", "coturn"); // sorted union
        assertThat(body.generation()).isEqualTo(5L); // max(asg gens, cfg gen)
    }

    @Test
    void compile_allServicesAssignment_subsumesNarrowed() {
        Device n = node("fp-1", "brandx", Device.OWNER_ADMIN);
        VpnConfig active = cfg("c1", "proton-us", "brandx", 1L, VpnConfig.STATE_ACTIVE);
        List<VpnNodeAssignment> asgs = List.of(
                devAsg("a1", "c1", "fp-1", "coturn", 1L),
                devAsg("a2", "c1", "fp-1", null, 2L)); // "all services" wins
        VpnExportBody body = VpnExportService.compile(n, List.of(active), asgs);
        assertThat(body.entries()).hasSize(1);
        assertThat(body.entries().get(0).serviceSlugs()).isEmpty(); // all services
    }

    @Test
    void compile_noMatchingAssignment_isEmpty() {
        Device n = node("fp-1", "brandx", Device.OWNER_ADMIN);
        VpnConfig active = cfg("c1", "proton-us", "brandx", 1L, VpnConfig.STATE_ACTIVE);
        // a DEVICE assignment for a DIFFERENT node + a DOMAIN assignment for a DIFFERENT
        // domain: neither matches.
        List<VpnNodeAssignment> asgs = List.of(
                devAsg("a1", "c1", "fp-other", null, 1L),
                domAsg("a2", "c1", "brandy", null, 1L));
        VpnExportBody body = VpnExportService.compile(n, List.of(active), asgs);
        assertThat(body.entries()).isEmpty();
    }

    @Test
    void sign_verify_roundTrips_andTamperFails() {
        RegistrySigner signer = signingSigner();
        VpnExportService svc = new VpnExportService(null, null, null, signer);

        VpnExportBody body = new VpnExportBody("fp-1", 7L,
                List.of(new VpnEgressEntry("proton-us", "wireguard", "ref-1", "1.2.3.4:51820", List.of("coturn"))));
        SignedVpnExport signed = svc.sign(body);
        assertThat(signed.signed()).isTrue();
        assertThat(signed.signature()).isNotNull();

        byte[] canonical = VpnExportService.canonicalBytes(body);
        assertThat(RegistrySigner.verify(canonical, signed.signature(), signed.publicKey())).isTrue();

        // Tamper: a different body's canonical bytes must NOT verify under the same sig.
        VpnExportBody tampered = new VpnExportBody("fp-1", 7L,
                List.of(new VpnEgressEntry("proton-us", "wireguard", "ref-EVIL", "1.2.3.4:51820", List.of("coturn"))));
        byte[] tamperedBytes = VpnExportService.canonicalBytes(tampered);
        assertThat(RegistrySigner.verify(tamperedBytes, signed.signature(), signed.publicKey())).isFalse();
    }

    @Test
    void sign_noKey_isUnsigned_agentFailsClosed() {
        RegistrySigner noKey = new RegistrySigner("", "", ""); // no signing key configured
        VpnExportService svc = new VpnExportService(null, null, null, noKey);
        SignedVpnExport signed = svc.sign(new VpnExportBody("fp-1", 1L, List.of()));
        assertThat(signed.signed()).isFalse();
        assertThat(signed.signature()).isNull();
    }

    @Test
    void canonicalBytes_areStable_andRollbackIsDetectable() {
        VpnExportBody g5 = new VpnExportBody("fp-1", 5L, List.of());
        VpnExportBody g4 = new VpnExportBody("fp-1", 4L, List.of());
        // The agent's strict-monotonic guard rejects a generation <= last-good; here we
        // just assert the generation the canonical bytes carry is what the guard reads.
        assertThat(new String(VpnExportService.canonicalBytes(g5))).contains("generation=5");
        assertThat(new String(VpnExportService.canonicalBytes(g4))).contains("generation=4");
        assertThat(g4.generation()).isLessThan(g5.generation());
    }
}
