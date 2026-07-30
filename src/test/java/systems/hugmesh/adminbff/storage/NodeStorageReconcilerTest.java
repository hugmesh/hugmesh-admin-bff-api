package systems.hugmesh.adminbff.storage;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.adminbff.device.Device;
import systems.hugmesh.adminbff.device.DeviceRegistryRepository;
import systems.hugmesh.adminbff.device.DeviceRegistryService;
import systems.hugmesh.adminbff.lease.LeaderElection;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Lease-gated single-writer node-storage reconciler over real H2 repos + a recording
 * ConfigMap writer + a toggleable fake leader. Proves the GameInstanceReconciler-cloned
 * contract for the assignments->ConfigMap bridge:
 * <ul>
 *   <li><b>not-leader skips entirely</b> (single-writer): no render, no propagation mutate;</li>
 *   <li><b>SHIPS SAFE / inert</b>: with ZERO active assignments the render is an EMPTY element
 *       list (preserves today's empty-ConfigMap state);</li>
 *   <li><b>renders the EXACT 13b element shape</b> resolving {@code poolPath} + {@code nodeName}
 *       (pool.deviceId -> Device.hostname), bytes->whole-Gi, state="active";</li>
 *   <li><b>forward-reconciles propagation_state</b>: applied on a successful write, failed on a
 *       writer failure (retried next tick);</li>
 *   <li><b>a revoked row drops out</b> of the rendered desired set (the unplace lever).</li>
 * </ul>
 * Mirrors {@code NodeStorageServiceTest} seeding (real H2 repos) + {@code GameInstanceReconcilerTest}
 * (FakeLeader + RecordingWriter).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class NodeStorageReconcilerTest {

    @Autowired DatabaseClient db;

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
    private static final String BRANDX = "https://idp.brandx.example";

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM storage_service_assignment").fetch().rowsUpdated().block();
        db.sql("DELETE FROM node_storage_pool").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
    }

    private DeviceRegistryRepository deviceRepo() {
        return new DeviceRegistryRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(
                db, systems.hugmesh.adminbff.device.DeviceRowRepository.class));
    }
    private StoragePoolRepository poolRepo() {
        return new StoragePoolRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(
                db, systems.hugmesh.adminbff.storage.StoragePoolR2dbcRepository.class));
    }
    private ServiceAssignmentRepository assignRepo() {
        return new ServiceAssignmentRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(
                db, systems.hugmesh.adminbff.storage.ServiceAssignmentR2dbcRepository.class));
    }
    private NodeStorageService svc() {
        return new NodeStorageService(poolRepo(), assignRepo(), deviceRepo());
    }

    private NodeStorageReconciler newReconciler(FakeLeader leader, RecordingWriter writer) {
        return new NodeStorageReconciler(assignRepo(), poolRepo(), deviceRepo(), leader, writer,
                "hugmesh-backend");
    }

    private static PrincipalDomain superadmin() {
        var jwt = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t")
                .header("alg", "none").issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(BRANDX).claim("roles", List.of("superadmin")).build();
        var auth = new org.springframework.security.oauth2.server.resource.authentication
                .JwtAuthenticationToken(jwt, List.of(
                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"),
                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private Device node(String fp, String hostname) {
        DeviceRegistryService devSvc = new DeviceRegistryService(deviceRepo(), REGISTRY, false);
        return devSvc.register(new Device(null, fp, hostname, "tn", Device.IMAGE_MESH_EXTENSION,
                "rpi5", Device.OWNER_ADMIN, "owner@brandx", "brandx", "mesh-1", null, null)).block();
    }

    /** Attach an active pool on a node + assign one active service to it. Returns the assignment. */
    private ServiceAssignment activeAssignment(Device dev, String poolPath, String service,
                                               String pvc, long bytes) {
        NodeStorageService svc = svc();
        StoragePool pool = svc.attachPool(dev.id(), "disk-" + service, poolPath, 100L * 1024 * 1024 * 1024,
                false, "ext4", superadmin(), "root").block();
        return svc.assignService(pool.id(), service, pvc, bytes, superadmin(), "root").block();
    }

    /** A leader gate we can flip. */
    static final class FakeLeader implements LeaderElection {
        boolean leader;
        FakeLeader(boolean leader) { this.leader = leader; }
        @Override public boolean isLeader() { return leader; }
        @Override public String label() { return "fake(leader=" + leader + ")"; }
    }

    /** Records every render call and can be forced to fail. */
    static final class RecordingWriter implements NodeStorageConfigMapWriter {
        final List<List<StorageAssignmentElement>> renders = new ArrayList<>();
        boolean failNext = false;
        @Override public boolean writeAssignments(List<StorageAssignmentElement> elements) {
            renders.add(List.copyOf(elements));
            return !failNext;
        }
        @Override public boolean isReal() { return true; }
        List<StorageAssignmentElement> last() { return renders.get(renders.size() - 1); }
    }

    @Test
    void notLeader_skipsEntirely_noRender() {
        Device dev = node("fp-n1", "pi-edge-01");
        activeAssignment(dev, "/mnt/pool-1", "owncast", "owncast-data", 4L * 1024 * 1024 * 1024);
        RecordingWriter writer = new RecordingWriter();

        newReconciler(new FakeLeader(false), writer).runOnce().block();

        assertThat(writer.renders).isEmpty();
    }

    @Test
    void leader_noAssignments_shipsInert_emptyRender() {
        // SHIPS SAFE: no active assignments => an empty element list (today's inert state).
        RecordingWriter writer = new RecordingWriter();

        newReconciler(new FakeLeader(true), writer).runOnce().block();

        assertThat(writer.renders).hasSize(1);
        assertThat(writer.last()).isEmpty();
    }

    @Test
    void leader_rendersExact13bElementShape_andMarksApplied() {
        Device dev = node("fp-n1", "pi-edge-01");
        ServiceAssignment a = activeAssignment(dev, "/mnt/pool-1", "owncast", "owncast-data",
                4L * 1024 * 1024 * 1024); // exactly 4Gi
        RecordingWriter writer = new RecordingWriter();

        newReconciler(new FakeLeader(true), writer).runOnce().block();

        assertThat(writer.renders).hasSize(1);
        assertThat(writer.last()).hasSize(1);
        StorageAssignmentElement e = writer.last().get(0);
        assertThat(e.id()).isEqualTo(a.id());
        assertThat(e.service()).isEqualTo("owncast");
        assertThat(e.pvc()).isEqualTo("owncast-data");
        assertThat(e.nodeName()).isEqualTo("pi-edge-01");   // resolved pool.deviceId -> hostname
        assertThat(e.poolPath()).isEqualTo("/mnt/pool-1");
        assertThat(e.namespace()).isEqualTo("hugmesh-backend");
        assertThat(e.requested()).isEqualTo("4");           // bytes -> whole Gi
        assertThat(e.state()).isEqualTo("active");

        // propagation_state forward-reconciled to applied.
        assertThat(assignRepo().findById(a.id()).block().propagationState())
                .isEqualTo(ServiceAssignment.PROP_APPLIED);
    }

    @Test
    void leader_writerFails_marksFailed_forRetry() {
        Device dev = node("fp-n1", "pi-edge-01");
        ServiceAssignment a = activeAssignment(dev, "/mnt/pool-1", "akkoma", "akkoma-data",
                1L); // sub-Gi -> rounds up to 1
        RecordingWriter writer = new RecordingWriter();
        writer.failNext = true;

        newReconciler(new FakeLeader(true), writer).runOnce().block();

        assertThat(writer.last()).hasSize(1);
        assertThat(writer.last().get(0).requested()).isEqualTo("1"); // ceil(1 byte) == 1Gi
        assertThat(assignRepo().findById(a.id()).block().propagationState())
                .isEqualTo(ServiceAssignment.PROP_FAILED);
    }

    @Test
    void revokedAssignment_dropsOutOfRenderedSet() {
        Device dev = node("fp-n1", "pi-edge-01");
        ServiceAssignment keep = activeAssignment(dev, "/mnt/pool-1", "owncast", "owncast-data",
                2L * 1024 * 1024 * 1024);
        ServiceAssignment gone = activeAssignment(dev, "/mnt/pool-2", "phpbb", "phpbb-data",
                2L * 1024 * 1024 * 1024);
        svc().revokeAssignment(gone.id(), superadmin(), "root").block();
        RecordingWriter writer = new RecordingWriter();

        newReconciler(new FakeLeader(true), writer).runOnce().block();

        assertThat(writer.last()).extracting(StorageAssignmentElement::id)
                .containsExactly(keep.id());
    }
}
