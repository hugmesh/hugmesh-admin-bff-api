package net.hugmesh.adminbff.device;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The HEADSCALE-ANCHORED register RE-VALIDATION matrix (machine_key_fp AUTO-CAPTURE). The
 * opaque fp the superadmin picked is re-queried against the live headscale node set at commit:
 *
 * <ul>
 *   <li><b>enabled + enforcing (allow-manual-fp=false): fp NOT enrolled → 409 fail-closed,
 *       NEVER inserts.</b> The headline safety test.</li>
 *   <li>enabled + enforcing: fp enrolled but WRONG mesh → 409 fail-closed.</li>
 *   <li>enabled + enforcing: fp enrolled + mesh matches → inserts.</li>
 *   <li>enabled + BREAK-GLASS (allow-manual-fp=true, ships dark): fp NOT enrolled → accepted
 *       anyway (advisory) → inserts.</li>
 *   <li>disabled (default): no re-query at all → inserts.</li>
 * </ul>
 *
 * Pure unit test — the {@link HeadscaleNodesClient} and {@link DeviceRegistryRepository} are
 * BOTH mocked (no live headscale binary, no DB), so it asserts the re-validate control flow in
 * isolation. The headscale CLI is NEVER invoked.
 */
class DeviceRegistryHeadscaleRevalidateTest {

    /** Genuinely multi-issuer so the FIX-NODEFAULT guard passes and we exercise re-validation. */
    private static final DomainRegistry MULTI = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private static Device device(String fp, String mesh) {
        return new Device(null, fp, "node-" + fp, "tn", Device.IMAGE_MESH_EXTENSION, "rpi5",
                Device.OWNER_ADMIN, "alice@brandx", "brandx", mesh, null, null);
    }

    private static HeadscaleNode enrolled(String fp, String meshTag) {
        return new HeadscaleNode(fp, "node", "brandx", meshTag);
    }

    private DeviceRegistryRepository repo() {
        DeviceRegistryRepository repo = mock(DeviceRegistryRepository.class);
        when(repo.findByMachineKey(anyString())).thenReturn(Mono.empty());
        when(repo.insert(any())).thenAnswer(inv -> {
            Device d = inv.getArgument(0);
            return Mono.just(new Device("id-" + d.machineKeyFp(), d.machineKeyFp(), d.hostname(),
                    d.tailnetId(), d.imageType(), d.hardwareClass(), d.ownerType(),
                    d.physicalOwner(), d.domain(), d.meshId(), null, null));
        });
        return repo;
    }

    private DeviceRegistryService svc(DeviceRegistryRepository repo, HeadscaleNodesClient hs,
                                      RegistryHeadscaleProperties props) {
        return new DeviceRegistryService(repo, MULTI, false, hs, props);
    }

    private static RegistryHeadscaleProperties enforcing() {
        RegistryHeadscaleProperties p = new RegistryHeadscaleProperties();
        p.setEnabled(true);
        p.setAllowManualFp(false);   // ENFORCING: a mismatch is fail-closed.
        return p;
    }

    @Test
    void enforcing_fpNotEnrolled_is409FailClosed_andNeverInserts() {
        DeviceRegistryRepository repo = repo();
        HeadscaleNodesClient hs = mock(HeadscaleNodesClient.class);
        // Headscale reports a DIFFERENT fp — the offered one is not enrolled.
        when(hs.listNodes()).thenReturn(Flux.just(enrolled("nodekey:OTHER", "tag:mesh_1")));
        DeviceRegistryService svc = svc(repo, hs, enforcing());

        StepVerifier.create(svc.register(device("nodekey:MISSING", "mesh-1")))
                .expectErrorSatisfies(e -> {
                    org.assertj.core.api.Assertions.assertThat(e).isInstanceOf(ApiException.class);
                    org.assertj.core.api.Assertions.assertThat(((ApiException) e).status().value()).isEqualTo(409);
                })
                .verify();
        verify(repo, never()).insert(any());
    }

    @Test
    void enforcing_fpEnrolledButWrongMesh_is409FailClosed() {
        DeviceRegistryRepository repo = repo();
        HeadscaleNodesClient hs = mock(HeadscaleNodesClient.class);
        // Enrolled, but headscale says it is in mesh_99, not the requested mesh-1.
        when(hs.listNodes()).thenReturn(Flux.just(enrolled("nodekey:HERE", "tag:mesh_99")));
        DeviceRegistryService svc = svc(repo, hs, enforcing());

        StepVerifier.create(svc.register(device("nodekey:HERE", "mesh-1")))
                .expectErrorSatisfies(e ->
                        org.assertj.core.api.Assertions.assertThat(((ApiException) e).status().value()).isEqualTo(409))
                .verify();
        verify(repo, never()).insert(any());
    }

    @Test
    void enforcing_fpEnrolledAndMeshMatches_inserts() {
        DeviceRegistryRepository repo = repo();
        HeadscaleNodesClient hs = mock(HeadscaleNodesClient.class);
        // Mesh tag "tag:mesh-1" contains the requested "mesh-1" → match.
        when(hs.listNodes()).thenReturn(Flux.just(enrolled("nodekey:OK", "tag:mesh-1")));
        DeviceRegistryService svc = svc(repo, hs, enforcing());

        StepVerifier.create(svc.register(device("nodekey:OK", "mesh-1")))
                .assertNext(d -> org.assertj.core.api.Assertions.assertThat(d.machineKeyFp()).isEqualTo("nodekey:OK"))
                .verifyComplete();
        verify(repo).insert(any());
    }

    @Test
    void breakGlass_fpNotEnrolled_acceptedAnyway_shipsDark() {
        DeviceRegistryRepository repo = repo();
        HeadscaleNodesClient hs = mock(HeadscaleNodesClient.class);
        when(hs.listNodes()).thenReturn(Flux.just(enrolled("nodekey:OTHER", "tag:mesh_1")));
        RegistryHeadscaleProperties breakGlass = new RegistryHeadscaleProperties();
        breakGlass.setEnabled(true);
        breakGlass.setAllowManualFp(true);   // DEFAULT ships-dark: advisory, accept on mismatch.
        DeviceRegistryService svc = svc(repo, hs, breakGlass);

        StepVerifier.create(svc.register(device("nodekey:MANUAL", "mesh-1")))
                .assertNext(d -> org.assertj.core.api.Assertions.assertThat(d.machineKeyFp()).isEqualTo("nodekey:MANUAL"))
                .verifyComplete();
        verify(repo).insert(any());   // accepted despite the mismatch (break-glass).
    }

    @Test
    void disabled_default_noReQuery_inserts() {
        DeviceRegistryRepository repo = repo();
        HeadscaleNodesClient hs = mock(HeadscaleNodesClient.class);
        // Feature OFF (default): listNodes() returns empty + must not even be relied upon.
        when(hs.listNodes()).thenReturn(Flux.empty());
        RegistryHeadscaleProperties off = new RegistryHeadscaleProperties();   // enabled=false default
        DeviceRegistryService svc = svc(repo, hs, off);

        StepVerifier.create(svc.register(device("nodekey:ANY", "mesh-1")))
                .assertNext(d -> org.assertj.core.api.Assertions.assertThat(d.machineKeyFp()).isEqualTo("nodekey:ANY"))
                .verifyComplete();
        verify(repo).insert(any());
    }
}
