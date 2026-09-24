package net.hugmesh.adminbff.tor;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.capability.DomainCapability;
import net.hugmesh.adminbff.capability.DomainCapabilityRepository;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.RegistrySigner;
import net.hugmesh.adminbff.tor.TorExportModels.SignedTorExport;
import net.hugmesh.adminbff.tor.TorExportModels.TorExportBody;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link TorExportService} — the runtime writer of a node's {@code /etc/hugmesh/tor/upstream}
 * and {@code /etc/hugmesh/tor/domains} (hugmesh-admin-bff-api#108):
 * <ul>
 *   <li>upstream is per node and unmanaged until a SUPERADMIN sets it; managed-null means
 *       "the agent's default" (an empty value the agent turns into removing the file);</li>
 *   <li>domains are mesh-wide from the {@code tor-onion} capability rows: unmanaged until
 *       the {@code ' global'} row exists, killed (empty) when it is not granted, and
 *       otherwise exactly the active, slug-shaped, non-default domains, sorted;</li>
 *   <li>generation strictly advances on a change to either side;</li>
 *   <li>an unknown fingerprint gets an empty, signed, unmanaged body and nothing is read;</li>
 *   <li>sign/verify round-trips over the canonical bytes; a tampered body fails.</li>
 * </ul>
 */
class TorExportServiceTest {

    private static RegistrySigner signingSigner() {
        KeyPair kp = RegistrySigner.ephemeral();
        return new RegistrySigner(Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()), "",
                Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));
    }

    private static DomainCapability cap(String domain, boolean granted, boolean enabled, long gen) {
        return new DomainCapability("id-" + domain, domain, DomainCapability.TOR_ONION, granted, enabled,
                "root", Instant.now(), gen);
    }

    private static DomainCapability global(boolean granted, long gen) {
        return cap(DomainCapability.GLOBAL_DOMAIN, granted, false, gen);
    }

    private static TorNodeConfig cfg(String upstream, long gen) {
        return new TorNodeConfig("fp-1", true, upstream, gen, "root", Instant.now());
    }

    private static Device node(String fp) {
        return new Device("id-" + fp, fp, "edge", "tn", Device.IMAGE_PRIMARY, "x86",
                Device.OWNER_SUPERADMIN, "root", "default", "mesh-1", Instant.now(), null);
    }

    @Test
    void noConfig_noGlobalRow_nothingIsManaged() {
        TorExportBody b = TorExportService.compile("fp-1", null,
                List.of(cap("brandb", true, true, 4L)));   // an active row, but no ' global' row
        assertThat(b.node()).isEqualTo("fp-1");
        assertThat(b.upstreamManaged()).isFalse();
        assertThat(b.upstream()).isEmpty();
        assertThat(b.domainsManaged()).isFalse();
        assertThat(b.domains()).isEmpty();
        assertThat(b.generation()).isEqualTo(4L);
    }

    @Test
    void managedUpstream_isCarried_andManagedNullIsTheAgentDefault() {
        assertThat(TorExportService.compile("fp-1", cfg("10.0.0.7:443", 3L), List.of()))
                .satisfies(b -> {
                    assertThat(b.upstreamManaged()).isTrue();
                    assertThat(b.upstream()).isEqualTo("10.0.0.7:443");
                    assertThat(b.generation()).isEqualTo(3L);
                });
        assertThat(TorExportService.compile("fp-1", cfg(null, 4L), List.of()))
                .satisfies(b -> {
                    assertThat(b.upstreamManaged()).isTrue();
                    assertThat(b.upstream()).isEmpty();
                });
        // a row that exists but is not managed stays unmanaged (defensive)
        TorNodeConfig unmanaged = new TorNodeConfig("fp-1", false, "10.0.0.7:443", 1L, "root", Instant.now());
        assertThat(TorExportService.compile("fp-1", unmanaged, List.of()).upstreamManaged()).isFalse();
        assertThat(TorExportService.compile("fp-1", unmanaged, List.of()).upstream()).isEmpty();
    }

    @Test
    void globalGranted_listsExactlyTheActiveSlugShapedNonDefaultDomains_sorted() {
        List<DomainCapability> rows = List.of(
                global(true, 1L),
                cap("zeta", true, true, 2L),
                cap("brandb", true, true, 3L),
                cap("granted-only", true, false, 4L),      // admin never opted in
                cap("enabled-only", false, true, 5L),      // superadmin never granted
                cap("default", true, true, 6L),            // the primary onion serves default
                cap("brand.c", true, true, 7L),            // the agent refuses a dotted slug
                new DomainCapability("x", "other", "user-mesh-devices", true, true, "root", Instant.now(), 99L));
        TorExportBody b = TorExportService.compile("fp-1", null, rows);
        assertThat(b.domainsManaged()).isTrue();
        assertThat(b.domains()).containsExactly("brandb", "zeta");
        // the unrelated capability row does not feed the generation
        assertThat(b.generation()).isEqualTo(7L);
    }

    @Test
    void globalNotGranted_isTheKillSwitch_managedAndEmpty() {
        TorExportBody b = TorExportService.compile("fp-1", null,
                List.of(global(false, 8L), cap("brandb", true, true, 3L)));
        assertThat(b.domainsManaged()).isTrue();
        assertThat(b.domains()).isEmpty();
    }

    @Test
    void generation_strictlyAdvancesOnAChangeToEitherSide() {
        List<DomainCapability> caps = new ArrayList<>(List.of(global(true, 5L), cap("brandb", true, true, 6L)));
        long g0 = TorExportService.compile("fp-1", cfg("10.0.0.7:443", 2L), caps).generation();
        // a superadmin upstream write bumps the node's config generation
        long g1 = TorExportService.compile("fp-1", cfg("10.0.0.8:443", 3L), caps).generation();
        // a capability flip is stamped with the next table-wide generation
        caps.set(1, cap("brandb", true, false, 7L));
        long g2 = TorExportService.compile("fp-1", cfg("10.0.0.8:443", 3L), caps).generation();
        assertThat(g1).isGreaterThan(g0);
        assertThat(g2).isGreaterThan(g1);
    }

    @Test
    void canonicalBytes_spellTheContract() {
        TorExportBody b = new TorExportBody("fp-1", 9L, true, "10.0.0.7:443", true, List.of("brandb", "zeta"));
        assertThat(new String(TorExportService.canonicalBytes(b), StandardCharsets.UTF_8)).isEqualTo(
                "v1-tor\nnode=fp-1\ngeneration=9\nupstream-managed=true\nupstream=10.0.0.7:443\n"
                        + "domains-managed=true\ndomain=brandb\ndomain=zeta\n");
        assertThat(new String(TorExportService.canonicalBytes(TorExportService.emptyBody()), StandardCharsets.UTF_8))
                .isEqualTo("v1-tor\nnode=\ngeneration=0\nupstream-managed=false\nupstream=\ndomains-managed=false\n");
    }

    @Test
    void sign_verify_roundTrips_andTamperFails() {
        TorExportService svc = new TorExportService(null, null, null, signingSigner());
        TorExportBody body = new TorExportBody("fp-1", 9L, true, "10.0.0.7:443", true, List.of("brandb"));
        SignedTorExport signed = svc.sign(body);
        assertThat(signed.signed()).isTrue();
        assertThat(RegistrySigner.verify(TorExportService.canonicalBytes(body), signed.signature(),
                signed.publicKey())).isTrue();
        TorExportBody evil = new TorExportBody("fp-1", 9L, true, "203.0.113.9:443", true, List.of("brandb"));
        assertThat(RegistrySigner.verify(TorExportService.canonicalBytes(evil), signed.signature(),
                signed.publicKey())).isFalse();
        TorExportBody extraDomain = new TorExportBody("fp-1", 9L, true, "10.0.0.7:443", true, List.of("brandb", "evil"));
        assertThat(RegistrySigner.verify(TorExportService.canonicalBytes(extraDomain), signed.signature(),
                signed.publicKey())).isFalse();
    }

    @Test
    void sign_noKey_isUnsigned() {
        TorExportService svc = new TorExportService(null, null, null, new RegistrySigner("", "", ""));
        SignedTorExport signed = svc.sign(TorExportService.emptyBody());
        assertThat(signed.signed()).isFalse();
        assertThat(signed.signature()).isNull();
    }

    @Test
    void exportNode_unknownFp_isEmptySignedUnmanaged_andReadsNothingElse() {
        DeviceRegistryRepository devices = mock(DeviceRegistryRepository.class);
        TorNodeConfigRowRepository configs = mock(TorNodeConfigRowRepository.class);
        DomainCapabilityRepository caps = mock(DomainCapabilityRepository.class);
        when(devices.findByMachineKey("nope")).thenReturn(Mono.empty());
        SignedTorExport out = new TorExportService(devices, configs, caps, signingSigner())
                .exportNode("nope").block();
        assertThat(out).isNotNull();
        assertThat(out.signed()).isTrue();
        assertThat(out.body()).isEqualTo(TorExportService.emptyBody());
        verify(configs, never()).findByMachineKeyFp(anyString());
        verify(caps, never()).listAll();
    }

    @Test
    void exportNode_knownSuperadminNode_isServed_withItsConfigAndTheMeshDomains() {
        DeviceRegistryRepository devices = mock(DeviceRegistryRepository.class);
        TorNodeConfigRowRepository configs = mock(TorNodeConfigRowRepository.class);
        DomainCapabilityRepository caps = mock(DomainCapabilityRepository.class);
        when(devices.findByMachineKey("fp-1")).thenReturn(Mono.just(node("fp-1")));
        when(configs.findByMachineKeyFp("fp-1")).thenReturn(Mono.just(
                new TorNodeConfigRow("c1", "fp-1", true, "10.0.0.7:443", 2L, "root", Instant.now())));
        when(caps.listAll()).thenReturn(Flux.just(global(true, 1L), cap("brandb", true, true, 3L),
                new DomainCapability("x", "brandz", "user-mesh-devices", true, true, "root", Instant.now(), 50L)));
        TorExportBody b = new TorExportService(devices, configs, caps, signingSigner())
                .exportNode("fp-1").block().body();
        assertThat(b.node()).isEqualTo("fp-1");
        assertThat(b.upstream()).isEqualTo("10.0.0.7:443");
        assertThat(b.domains()).containsExactly("brandb");
        assertThat(b.generation()).isEqualTo(5L);
    }

    @Test
    void exportNode_knownNodeWithoutConfig_managesNoUpstream() {
        DeviceRegistryRepository devices = mock(DeviceRegistryRepository.class);
        TorNodeConfigRowRepository configs = mock(TorNodeConfigRowRepository.class);
        DomainCapabilityRepository caps = mock(DomainCapabilityRepository.class);
        when(devices.findByMachineKey("fp-2")).thenReturn(Mono.just(node("fp-2")));
        when(configs.findByMachineKeyFp("fp-2")).thenReturn(Mono.empty());
        when(caps.listAll()).thenReturn(Flux.empty());
        TorExportBody b = new TorExportService(devices, configs, caps, signingSigner())
                .exportNode("fp-2").block().body();
        assertThat(b.node()).isEqualTo("fp-2");
        assertThat(b.upstreamManaged()).isFalse();
        assertThat(b.domainsManaged()).isFalse();
        assertThat(b.generation()).isZero();
    }
}
