package net.hugmesh.adminbff.storage;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.DeviceRegistryService;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link NodeStorageService} over a Liquibase-applied H2 (PG-compat) store. Proves the
 * required acceptance bar for the NODE STORAGE control plane:
 * <ul>
 *   <li><b>OWNERSHIP ALLOW/DENY matrix</b> (the load-bearing security): SUPERADMIN
 *       unrestricted; ADMIN allowed ONLY on own-domain ADMIN-owned nodes; ADMIN DENIED a
 *       SUPERADMIN-owned node (403) and DENIED a cross-domain node (403);</li>
 *   <li><b>per-domain isolation</b> on the read surface (a brand-Y admin cannot see a
 *       brand-X pool/assignment; SUPERADMIN sees all);</li>
 *   <li><b>over-subscription reject</b> (a placement exceeding reserved_bytes is 422; an
 *       exclusive pool rejects a second active assignment);</li>
 *   <li><b>FIX-NODEFAULT</b> domain stamping from the node's/pool's RESIDENCY, never the
 *       caller;</li>
 *   <li><b>idempotent</b> attach/assign + <b>CAS</b> detach/revoke (never DELETE = audit).</li>
 * </ul>
 * Mirrors {@code SshLicenseServiceDomainScopeTest} wiring (real H2 repos, JWT-derived
 * {@link PrincipalDomain}).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class NodeStorageServiceTest {

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM storage_service_assignment").fetch().rowsUpdated().block();
        db.sql("DELETE FROM node_storage_pool").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
    private static final String BRANDX = "https://idp.brandx.example";
    private static final String BRANDY = "https://idp.brandy.example";

    private DeviceRegistryRepository deviceRepo() { return new DeviceRegistryRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.device.DeviceRowRepository.class)); }
    private StoragePoolRepository poolRepo() { return new StoragePoolRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.storage.StoragePoolR2dbcRepository.class)); }
    private ServiceAssignmentRepository assignRepo() { return new ServiceAssignmentRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.storage.ServiceAssignmentR2dbcRepository.class)); }
    private NodeStorageService svc() {
        return new NodeStorageService(poolRepo(), assignRepo(), deviceRepo());
    }

    /** Register an ADMIN-owned mesh node in a brand. */
    private Device adminNode(String fp, String domain) {
        return register(fp, domain, Device.OWNER_ADMIN, Device.IMAGE_MESH_EXTENSION);
    }

    /** Register a SUPERADMIN-owned (core) node in a brand. */
    private Device superNode(String fp, String domain) {
        return register(fp, domain, Device.OWNER_SUPERADMIN, Device.IMAGE_PRIMARY);
    }

    private Device register(String fp, String domain, String ownerType, String imageType) {
        DeviceRegistryService devSvc = new DeviceRegistryService(deviceRepo(), REGISTRY, false);
        return devSvc.register(new Device(null, fp, "node-" + fp, "tn", imageType, "rpi5",
                ownerType, "owner@" + domain, domain, "mesh-1", null, null)).block();
    }

    private static PrincipalDomain admin(String issuer) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(issuer).claim("roles", List.of("admin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static PrincipalDomain superadmin() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(BRANDX).claim("roles", List.of("superadmin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    // ════════════════════════ OWNERSHIP ALLOW/DENY ═════════════════════════════
    @Nested
    class OwnershipMatrix {

        @Test
        void admin_ownDomain_adminOwnedNode_isAllowed() {
            // ALLOW: a brandx ADMIN attaches a pool to a brandx ADMIN-owned node.
            NodeStorageService svc = svc();
            Device node = adminNode("fp-ax", "brandx");
            StoragePool pool = svc.attachPool(node.id(), "disk-1", "/p1", 10_000, false, "ext4",
                    admin(BRANDX), "alice@brandx").block();
            assertThat(pool).isNotNull();
            assertThat(pool.domain()).isEqualTo("brandx");   // FIX-NODEFAULT: from residency
            assertThat(pool.isActive()).isTrue();
        }

        @Test
        void admin_superadminOwnedNode_isDenied403_evenInOwnDomain() {
            // DENY: an ADMIN may NOT touch a SUPERADMIN-owned node, even in their own brand.
            NodeStorageService svc = svc();
            Device core = superNode("fp-core", "brandx");
            assertThatThrownBy(() -> svc.attachPool(core.id(), "disk-1", "/p", 10_000, false, "ext4",
                    admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(StorageAccessDeniedException.class)
                    .hasMessageContaining("SUPERADMIN-owned");

            // No pool row was written for the denied attach.
            Long rows = db.sql("SELECT COUNT(*) AS c FROM node_storage_pool WHERE device_id = :d")
                    .bind("d", core.id()).map((r, m) -> r.get("c", Long.class)).first().block();
            assertThat(rows).isZero();
        }

        @Test
        void admin_crossDomainNode_isDenied403() {
            // DENY: a brandx ADMIN may NOT touch a brandy ADMIN-owned node (cross-domain).
            NodeStorageService svc = svc();
            Device brandyNode = adminNode("fp-ay", "brandy");
            assertThatThrownBy(() -> svc.attachPool(brandyNode.id(), "disk-1", "/p", 10_000, false, "ext4",
                    admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(StorageAccessDeniedException.class)
                    .hasMessageContaining("own-domain");
        }

        @Test
        void superadmin_isUnrestricted_anyOwnerAnyDomain() {
            // ALLOW (x3): SUPERADMIN attaches to an ADMIN-owned brandx node, an ADMIN-owned
            // brandy node, AND a SUPERADMIN-owned core node — unrestricted.
            NodeStorageService svc = svc();
            Device ax = adminNode("fp-sx", "brandx");
            Device ay = adminNode("fp-sy", "brandy");
            Device core = superNode("fp-sc", "brandx");

            assertThat(svc.attachPool(ax.id(), "d", "/p", 10_000, false, "ext4", superadmin(), "root").block())
                    .isNotNull();
            assertThat(svc.attachPool(ay.id(), "d", "/p", 10_000, false, "ext4", superadmin(), "root").block())
                    .isNotNull();
            assertThat(svc.attachPool(core.id(), "d", "/p", 10_000, false, "ext4", superadmin(), "root").block())
                    .isNotNull();
        }

        @Test
        void denyReason_purePredicate_coversTheWholeMatrix() {
            // The pure predicate (unit-tested in isolation) IS the matrix.
            Device adminBrandx = new Device("d1", "fp", "h", "tn", Device.IMAGE_MESH_EXTENSION,
                    "rpi5", Device.OWNER_ADMIN, "o", "brandx", "mesh-1", null, null);
            Device superBrandx = new Device("d2", "fp", "h", "tn", Device.IMAGE_PRIMARY,
                    "rpi5", Device.OWNER_SUPERADMIN, "o", "brandx", "mesh-1", null, null);

            // SUPERADMIN: always allowed.
            assertThat(NodeStorageService.denyReason(superadmin(), adminBrandx)).isNull();
            assertThat(NodeStorageService.denyReason(superadmin(), superBrandx)).isNull();
            // ADMIN own-domain admin-owned: allowed.
            assertThat(NodeStorageService.denyReason(admin(BRANDX), adminBrandx)).isNull();
            // ADMIN on superadmin-owned: denied.
            assertThat(NodeStorageService.denyReason(admin(BRANDX), superBrandx)).contains("SUPERADMIN-owned");
            // ADMIN cross-domain: denied.
            assertThat(NodeStorageService.denyReason(admin(BRANDY), adminBrandx)).contains("own-domain");
        }
    }

    // ════════════════════════ assign + over-subscription ═══════════════════════
    @Nested
    class AssignAndCapacity {

        @Test
        void assign_underReserved_isAllowed_andStampsPoolResidency() {
            NodeStorageService svc = svc();
            Device node = adminNode("fp-cap", "brandx");
            StoragePool pool = svc.attachPool(node.id(), "d", "/p", 10_000, false, "ext4",
                    admin(BRANDX), "alice@brandx").block();

            ServiceAssignment a = svc.assignService(pool.id(), "owncast", "owncast-data", 4_000,
                    admin(BRANDX), "alice@brandx").block();
            assertThat(a).isNotNull();
            assertThat(a.domain()).isEqualTo("brandx");   // FIX-NODEFAULT: from the pool's residency
            assertThat(a.isActive()).isTrue();
        }

        @Test
        void assign_overSubscription_isRejected422_andWritesNoRow() {
            NodeStorageService svc = svc();
            Device node = adminNode("fp-over", "brandx");
            StoragePool pool = svc.attachPool(node.id(), "d", "/p", 10_000, false, "ext4",
                    admin(BRANDX), "alice@brandx").block();
            // First placement commits 7000 of 10000.
            svc.assignService(pool.id(), "svc-a", "pvc-a", 7_000, admin(BRANDX), "alice@brandx").block();
            // Second placement (5000) would exceed reserved (7000+5000 > 10000) -> reject.
            assertThatThrownBy(() -> svc.assignService(pool.id(), "svc-b", "pvc-b", 5_000,
                    admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("over-subscription");

            Long rows = db.sql("SELECT COUNT(*) AS c FROM storage_service_assignment "
                            + "WHERE service_name = 'svc-b'")
                    .map((r, m) -> r.get("c", Long.class)).first().block();
            assertThat(rows).isZero();
        }

        @Test
        void assign_exactlyAtReserved_isAllowed() {
            // The boundary: committed + requested == reserved is allowed (<=, not <).
            NodeStorageService svc = svc();
            Device node = adminNode("fp-exact", "brandx");
            StoragePool pool = svc.attachPool(node.id(), "d", "/p", 10_000, false, "ext4",
                    admin(BRANDX), "alice@brandx").block();
            svc.assignService(pool.id(), "svc-a", "pvc-a", 6_000, admin(BRANDX), "alice@brandx").block();
            ServiceAssignment b = svc.assignService(pool.id(), "svc-b", "pvc-b", 4_000,
                    admin(BRANDX), "alice@brandx").block();
            assertThat(b).isNotNull();
        }

        @Test
        void assign_exclusivePool_rejectsSecondAssignment() {
            NodeStorageService svc = svc();
            Device node = adminNode("fp-excl", "brandx");
            StoragePool pool = svc.attachPool(node.id(), "d", "/p", 100_000, true /*exclusive*/, "ext4",
                    admin(BRANDX), "alice@brandx").block();
            svc.assignService(pool.id(), "video-svc", "video-data", 1_000, admin(BRANDX), "alice@brandx").block();
            // Even though there's plenty of room, an exclusive pool allows only ONE service.
            assertThatThrownBy(() -> svc.assignService(pool.id(), "other-svc", "other-data", 1_000,
                    admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("exclusive");
        }

        @Test
        void assign_onCrossDomainPool_isDenied403() {
            // The ownership gate fires on the pool's NODE for assign too — a brandx admin
            // cannot assign onto a pool pinned to a brandy node.
            NodeStorageService svc = svc();
            Device brandyNode = adminNode("fp-y2", "brandy");
            StoragePool pool = svc.attachPool(brandyNode.id(), "d", "/p", 10_000, false, "ext4",
                    superadmin(), "root").block();   // superadmin attaches it
            assertThatThrownBy(() -> svc.assignService(pool.id(), "svc", "pvc", 1_000,
                    admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(StorageAccessDeniedException.class);
        }
    }

    // ════════════════════════ idempotency + CAS ════════════════════════════════
    @Nested
    class IdempotencyAndCas {

        @Test
        void attachPool_isIdempotent_onActiveDeviceDisk() {
            NodeStorageService svc = svc();
            Device node = adminNode("fp-idem", "brandx");
            StoragePool first = svc.attachPool(node.id(), "disk-dup", "/p", 10_000, false, "ext4",
                    admin(BRANDX), "alice@brandx").block();
            StoragePool again = svc.attachPool(node.id(), "disk-dup", "/p", 10_000, false, "ext4",
                    admin(BRANDX), "alice@brandx").block();
            assertThat(again.id()).isEqualTo(first.id());
            Long count = db.sql("SELECT COUNT(*) AS c FROM node_storage_pool "
                            + "WHERE device_id = :d AND disk_serial = 'disk-dup' AND state = 'active'")
                    .bind("d", node.id()).map((r, m) -> r.get("c", Long.class)).first().block();
            assertThat(count).isEqualTo(1L);
        }

        @Test
        void assignService_isIdempotent_onActivePoolService() {
            NodeStorageService svc = svc();
            Device node = adminNode("fp-idem2", "brandx");
            StoragePool pool = svc.attachPool(node.id(), "d", "/p", 10_000, false, "ext4",
                    admin(BRANDX), "alice@brandx").block();
            ServiceAssignment first = svc.assignService(pool.id(), "svc", "pvc", 1_000,
                    admin(BRANDX), "alice@brandx").block();
            ServiceAssignment again = svc.assignService(pool.id(), "svc", "pvc", 1_000,
                    admin(BRANDX), "alice@brandx").block();
            assertThat(again.id()).isEqualTo(first.id());
        }

        @Test
        void revokeAssignment_isCas_winnerThenNoop_neverDeletes_bumpsGeneration() {
            NodeStorageService svc = svc();
            Device node = adminNode("fp-rev", "brandx");
            StoragePool pool = svc.attachPool(node.id(), "d", "/p", 10_000, false, "ext4",
                    admin(BRANDX), "alice@brandx").block();
            ServiceAssignment a = svc.assignService(pool.id(), "svc", "pvc", 1_000,
                    admin(BRANDX), "alice@brandx").block();
            long genBefore = a.generation();

            assertThat(svc.revokeAssignment(a.id(), admin(BRANDX), "alice@brandx").block()).isEqualTo(1L);
            assertThat(svc.revokeAssignment(a.id(), admin(BRANDX), "alice@brandx").block()).isEqualTo(0L);

            ServiceAssignment after = assignRepo().findById(a.id()).block();
            assertThat(after).isNotNull();
            assertThat(after.state()).isEqualTo(ServiceAssignment.STATE_REVOKED);
            assertThat(after.revokedBy()).isEqualTo("alice@brandx");
            assertThat(after.generation()).isGreaterThan(genBefore);
            assertThat(after.propagationState()).isEqualTo(ServiceAssignment.PROP_PENDING);
        }

        @Test
        void detachPool_refusedWhileActiveAssignmentExists_thenAllowedAfterRevoke() {
            NodeStorageService svc = svc();
            Device node = adminNode("fp-det", "brandx");
            StoragePool pool = svc.attachPool(node.id(), "d", "/p", 10_000, false, "ext4",
                    admin(BRANDX), "alice@brandx").block();
            ServiceAssignment a = svc.assignService(pool.id(), "svc", "pvc", 1_000,
                    admin(BRANDX), "alice@brandx").block();

            // Refused: a node-pinned PV would be orphaned.
            assertThatThrownBy(() -> svc.detachPool(pool.id(), admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("active assignment");

            // After revoking the assignment, detach succeeds (CAS).
            svc.revokeAssignment(a.id(), admin(BRANDX), "alice@brandx").block();
            assertThat(svc.detachPool(pool.id(), admin(BRANDX), "alice@brandx").block()).isEqualTo(1L);
            StoragePool after = poolRepo().findById(pool.id()).block();
            assertThat(after.state()).isEqualTo(StoragePool.STATE_DETACHED);
        }
    }

    // ════════════════════════ per-domain isolation ═════════════════════════════
    @Nested
    class TenantIsolation {

        @Test
        void admin_readsOwnDomainOnly_crossDomainEmpty_superadminSeesAll() {
            NodeStorageService svc = svc();
            Device nx = adminNode("fp-tx", "brandx");
            Device ny = adminNode("fp-ty", "brandy");
            // superadmin attaches a pool in each brand + an assignment in each.
            StoragePool px = svc.attachPool(nx.id(), "d", "/p", 10_000, false, "ext4", superadmin(), "root").block();
            StoragePool py = svc.attachPool(ny.id(), "d", "/p", 10_000, false, "ext4", superadmin(), "root").block();
            svc.assignService(px.id(), "svc-x", "pvc-x", 1_000, superadmin(), "root").block();
            svc.assignService(py.id(), "svc-y", "pvc-y", 1_000, superadmin(), "root").block();

            // brandx admin sees ONLY the brandx pool + assignment.
            assertThat(svc.listPools(admin(BRANDX)).collectList().block())
                    .extracting(StoragePool::domain).containsExactly("brandx");
            assertThat(svc.listAssignments(admin(BRANDX)).collectList().block())
                    .extracting(ServiceAssignment::serviceName).containsExactly("svc-x");

            // brandy admin sees ONLY brandy — the brandx rows are invisible (cross-domain DENY).
            assertThat(svc.listAssignments(admin(BRANDY)).collectList().block())
                    .extracting(ServiceAssignment::serviceName).containsExactly("svc-y");

            // SUPERADMIN (unscoped) sees both.
            assertThat(svc.listPools(superadmin()).collectList().block()).hasSize(2);
            assertThat(svc.listAssignments(superadmin()).collectList().block())
                    .extracting(ServiceAssignment::serviceName)
                    .containsExactlyInAnyOrder("svc-x", "svc-y");
        }
    }

    // ════════════════════════ unknown node / validation ════════════════════════
    @Nested
    class Validation {

        @Test
        void attach_onUnregisteredNode_isRejected422() {
            NodeStorageService svc = svc();
            assertThatThrownBy(() -> svc.attachPool("no-such-node", "d", "/p", 10_000, false, "ext4",
                    superadmin(), "root").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not registered");
        }

        @Test
        void attach_nonPositiveReserved_isRejected422() {
            NodeStorageService svc = svc();
            Device node = adminNode("fp-zero", "brandx");
            assertThatThrownBy(() -> svc.attachPool(node.id(), "d", "/p", 0, false, "ext4",
                    admin(BRANDX), "alice@brandx").block())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("reservedBytes");
        }
    }
}
