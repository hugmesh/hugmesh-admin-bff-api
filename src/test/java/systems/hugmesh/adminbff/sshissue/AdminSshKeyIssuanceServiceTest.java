package systems.hugmesh.adminbff.sshissue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.device.DeviceRegistryExportService;
import systems.hugmesh.adminbff.device.DeviceRegistryRepository;
import systems.hugmesh.adminbff.device.ExportModels.AuthorizedOperator;
import systems.hugmesh.adminbff.device.ExportModels.SignedExport;
import systems.hugmesh.adminbff.device.RegistrySigner;
import systems.hugmesh.adminbff.device.SshLicenseRepository;
import systems.hugmesh.adminbff.device.SshLicenseService;
import systems.hugmesh.adminbff.lease.LeaderElection;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The admin SSH key-ISSUANCE service over a Liquibase-applied H2 with REAL repositories + the
 * REAL {@link SshLicenseService} + the REAL {@link DeviceRegistryExportService} — so the
 * end-to-end mechanism is proven, NOT mocked:
 *
 * <ul>
 *   <li>SHIPS DARK: flag-off issue/download/revoke refuse and NEVER mint a key (no license/audit
 *       row written).</li>
 *   <li>AUTHZ (real even while dark): unregistered / cross-tenant / SUPERADMIN-owned device DENY.</li>
 *   <li>ISSUE -> the fingerprint is in the backing license AND appears in the signed node export
 *       (the node would authorize the offered key); REVOKE -> it is gone from both (clone of the
 *       DeviceRegistryExportServiceTest acceptance shape).</li>
 *   <li>ROTATION-REPLACES: a second issue for the SAME (operator, device) revokes the prior
 *       credential + drops its fingerprint, keeping the active set bounded.</li>
 *   <li>SINGLE-USE leader-pinned download: 1st delivers, 2nd is 410-Gone; a non-leader can
 *       neither issue nor deliver.</li>
 *   <li>NO-PRIVATE-KEY-IN-LOGS: even across issue + download the captured log NEVER contains the
 *       PEM marker.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
class AdminSshKeyIssuanceServiceTest {

    @Autowired DatabaseClient db;

    private static final String DEV_X = "dev-x-1";       // brandx, ADMIN-owned
    private static final String DEV_Y = "dev-y-1";       // brandy, ADMIN-owned
    private static final String DEV_SA = "dev-sa-1";     // brandx, SUPERADMIN-owned
    private static final String MK_X = "mk-x";

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private DeviceRegistryRepository devices;
    private SshLicenseRepository licenses;
    private SshLicenseService licenseService;
    private AdminSshIssuedKeyRepository issued;
    private DeviceRegistryExportService export;

    private ListAppender<ILoggingEvent> appender;
    private Logger rootLogger;

    static final class ToggleLeader implements LeaderElection {
        volatile boolean leader = true;
        public boolean isLeader() { return leader; }
        public String label() { return "test"; }
    }

    private final ToggleLeader leader = new ToggleLeader();

    @BeforeEach
    void setup() {
        db.sql("DELETE FROM admin_ssh_issued_key").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_ssh_license").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
        insertDevice(DEV_X, MK_X, "brandx", "ADMIN");
        insertDevice(DEV_Y, "mk-y", "brandy", "ADMIN");
        insertDevice(DEV_SA, "mk-sa", "brandx", "SUPERADMIN");

        devices = new DeviceRegistryRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.device.DeviceRowRepository.class));
        licenses = new SshLicenseRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.device.SshLicenseRowRepository.class));
        licenseService = new SshLicenseService(licenses, devices, REGISTRY);
        issued = new AdminSshIssuedKeyRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.sshissue.AdminSshIssuedKeyRowRepository.class));
        // No signing key (all empty) — the export body is what we assert; the unsigned envelope
        // is irrelevant to the fingerprint-in-body check (NO key is ever committed).
        RegistrySigner signer = new RegistrySigner("", "", "");
        export = new DeviceRegistryExportService(devices, licenses, signer);

        leader.leader = true;
        rootLogger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        appender = new ListAppender<>();
        // Capture into a thread-safe, snapshot-iterating list: under real Postgres the
        // r2dbc/netty connection lifecycle logs from async threads, so assertNoPemInLogs()
        // iterating a plain ArrayList raced into ConcurrentModificationException. (H2's
        // synchronous in-process client never exposed this.) CopyOnWriteArrayList makes
        // both the concurrent appends and the assertion's iteration safe.
        appender.list = new java.util.concurrent.CopyOnWriteArrayList<>();
        appender.start();
        rootLogger.addAppender(appender);
        rootLogger.setLevel(Level.TRACE);
    }

    @AfterEach
    void teardown() {
        rootLogger.detachAppender(appender);
        // FK-safe teardown so the SHARED H2 context does not leak device_ssh_license /
        // admin_ssh_issued_key rows referencing dev-x-1/dev-y-1 into the next @DataR2dbcTest
        // class (whose device_registry cleanup does not clear these child tables).
        db.sql("DELETE FROM admin_ssh_issued_key").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_ssh_license").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
    }

    private void insertDevice(String id, String mk, String domain, String owner) {
        db.sql("INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, "
                        + " domain, mesh_id, last_seen_at) "
                        + "VALUES (:id, :mk, :h, 'mesh-extension', :owner, 'o', :domain, 'mesh-1', now())")
                .bind("id", id).bind("mk", mk).bind("h", id).bind("owner", owner).bind("domain", domain)
                .fetch().rowsUpdated().block();
    }

    private AdminSshKeyIssuanceService svc(boolean enabled) {
        return new AdminSshKeyIssuanceService(enabled, devices, licenses, licenseService, issued, leader);
    }

    private PrincipalDomain superadmin() {
        return PrincipalDomain.superadminFor("brandx");
    }

    private PrincipalDomain brandXAdmin() {
        // scoped (non-superadmin) brand-x principal
        return PrincipalDomain.of(systems.hugmesh.adminbff.sshissue.TestAuth.admin(
                "https://idp.brandx.example"), REGISTRY);
    }

    private List<String> nodeFingerprints(String machineKeyFp) {
        SignedExport ex = export.exportNode(machineKeyFp).block();
        return ex.body().operators().stream()
                .flatMap(o -> o.keyFingerprints().stream())
                .toList();
    }

    private List<AuthorizedOperator> nodeOperators(String machineKeyFp) {
        return export.exportNode(machineKeyFp).block().body().operators();
    }

    // ── SHIPS DARK ────────────────────────────────────────────────────────────────
    @Nested
    class ShipsDark {
        @Test
        void darkIssue_refuses_andMintsNothing() {
            StepVerifier.create(svc(false).issue("alice", DEV_X, superadmin()))
                    .expectError(AdminSshKeyIssuanceService.SshIssueDarkException.class).verify();
            // NO license, NO audit row written, NO export entry.
            assertThat(licenses.listActiveAll().collectList().block()).isEmpty();
            assertThat(issued.findActiveForDevice(DEV_X, superadmin()).collectList().block()).isEmpty();
            assertThat(nodeOperators(MK_X)).isEmpty();
            // NO PEM ever appears in logs (no keygen happened).
            assertNoPemInLogs();
        }

        @Test
        void darkRevoke_refuses() {
            StepVerifier.create(svc(false).revoke("alice", "whatever", superadmin()))
                    .expectError(AdminSshKeyIssuanceService.SshIssueDarkException.class).verify();
        }
    }

    // ── AUTHZ (real even while dark) ────────────────────────────────────────────────
    @Nested
    class Authorization {
        @Test
        void unregisteredDevice_denied() {
            StepVerifier.create(svc(true).issue("alice", "nope", superadmin()))
                    .expectError(AdminSshKeyIssuanceService.SshIssueDeniedException.class).verify();
        }

        @Test
        void crossTenantDevice_denied() {
            // a brand-x scoped admin cannot issue for a brand-y device.
            StepVerifier.create(svc(true).issue("alice", DEV_Y, brandXAdmin()))
                    .expectError(AdminSshKeyIssuanceService.SshIssueDeniedException.class).verify();
            assertThat(licenses.listActiveAll().collectList().block()).isEmpty();
        }

        @Test
        void superadminOwnedNode_denied() {
            StepVerifier.create(svc(true).issue("alice", DEV_SA, superadmin()))
                    .expectError(AdminSshKeyIssuanceService.SshIssueDeniedException.class).verify();
            assertThat(licenses.listActiveAll().collectList().block()).isEmpty();
        }

        @Test
        void nonLeader_cannotIssue() {
            leader.leader = false;
            StepVerifier.create(svc(true).issue("alice", DEV_X, superadmin()))
                    .expectError(AdminSshKeyIssuanceService.SshIssueDeniedException.class).verify();
        }
    }

    // ── ISSUE -> export carries fp; REVOKE -> export drops it ───────────────────────
    @Nested
    class IssueRevokeExport {
        @Test
        void issue_addsFingerprintToBackingLicenseAndExport() {
            AdminSshKeyIssuanceService.IssueResult r = svc(true).issue("alice", DEV_X, superadmin()).block();
            assertThat(r.issuedKeyId()).isNotBlank();
            assertThat(r.fingerprint()).startsWith("SHA256:");
            assertThat(r.publicKey()).startsWith("ssh-ed25519 ");

            // the backing license now pins this fp, and the node export carries it.
            assertThat(licenses.listActiveAll().collectList().block()).hasSize(1);
            assertThat(nodeFingerprints(MK_X)).contains(r.fingerprint());
            assertNoPemInLogs();
        }

        @Test
        void revoke_dropsFingerprintFromExport() {
            AdminSshKeyIssuanceService s = svc(true);
            AdminSshKeyIssuanceService.IssueResult r = s.issue("alice", DEV_X, superadmin()).block();
            assertThat(nodeFingerprints(MK_X)).contains(r.fingerprint());

            assertThat(s.revoke("sa", r.issuedKeyId(), superadmin()).block()).isEqualTo(1L);
            // it was the only fp -> the whole license is revoked -> export carries nothing.
            assertThat(nodeFingerprints(MK_X)).doesNotContain(r.fingerprint());
            assertThat(nodeOperators(MK_X)).isEmpty();
            assertThat(issued.findById(r.issuedKeyId()).block().isIssued()).isFalse();
        }

        @Test
        void rotationReplacesPrior_forSameOperatorDevice() {
            AdminSshKeyIssuanceService s = svc(true);
            AdminSshKeyIssuanceService.IssueResult first = s.issue("alice", DEV_X, superadmin()).block();
            AdminSshKeyIssuanceService.IssueResult second = s.issue("alice", DEV_X, superadmin()).block();

            // exactly ONE active issued credential remains (the second); the first is revoked.
            List<AdminSshIssuedKey> active = issued.findActiveForDevice(DEV_X, superadmin()).collectList().block();
            assertThat(active).hasSize(1);
            assertThat(active.get(0).id()).isEqualTo(second.issuedKeyId());
            assertThat(issued.findById(first.issuedKeyId()).block().isIssued()).isFalse();

            // the export pins the SECOND fp, not the FIRST (bounded active set).
            assertThat(nodeFingerprints(MK_X)).contains(second.fingerprint());
            assertThat(nodeFingerprints(MK_X)).doesNotContain(first.fingerprint());
        }
    }

    // ── SINGLE-USE leader-pinned download ──────────────────────────────────────────
    @Nested
    class Download {
        @Test
        void download_isSingleUse_secondIs410() {
            AdminSshKeyIssuanceService s = svc(true);
            AdminSshKeyIssuanceService.IssueResult r = s.issue("alice", DEV_X, superadmin()).block();

            byte[] pem = s.downloadPrivateKey("alice", r.issuedKeyId()).block();
            assertThat(new String(pem)).startsWith("-----BEGIN OPENSSH PRIVATE KEY-----");

            // second download -> Gone (consumed).
            StepVerifier.create(s.downloadPrivateKey("alice", r.issuedKeyId()))
                    .expectError(AdminSshKeyIssuanceService.SshIssueGoneException.class).verify();
            // audit row stamped downloaded_at.
            assertThat(issued.findById(r.issuedKeyId()).block().isDownloaded()).isTrue();
            assertNoPemInLogs();
        }

        @Test
        void download_byWrongSubject_isGone() {
            AdminSshKeyIssuanceService s = svc(true);
            AdminSshKeyIssuanceService.IssueResult r = s.issue("alice", DEV_X, superadmin()).block();
            // a different subject cannot consume alice's held key.
            StepVerifier.create(s.downloadPrivateKey("mallory", r.issuedKeyId()))
                    .expectError(AdminSshKeyIssuanceService.SshIssueGoneException.class).verify();
        }

        @Test
        void download_onNonLeader_isGone() {
            AdminSshKeyIssuanceService s = svc(true);
            AdminSshKeyIssuanceService.IssueResult r = s.issue("alice", DEV_X, superadmin()).block();
            leader.leader = false;   // a leader flip drops delivery on this replica.
            StepVerifier.create(s.downloadPrivateKey("alice", r.issuedKeyId()))
                    .expectError(AdminSshKeyIssuanceService.SshIssueGoneException.class).verify();
        }
    }

    private void assertNoPemInLogs() {
        for (ILoggingEvent ev : appender.list) {
            assertThat(ev.getFormattedMessage()).doesNotContain("OPENSSH PRIVATE KEY");
            assertThat(ev.getFormattedMessage()).doesNotContain("BEGIN OPENSSH");
        }
    }
}
