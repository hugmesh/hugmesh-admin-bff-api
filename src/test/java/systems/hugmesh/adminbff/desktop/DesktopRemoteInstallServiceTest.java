package systems.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.device.DeviceRegistryRepository;
import systems.hugmesh.adminbff.device.SshLicenseRepository;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The REMOTE-INSTALL authorization keystone over a real H2 — proves the fail-closed
 * device-ssh-license gate (the load-bearing security boundary) using the REAL device_registry
 * + device_ssh_license tables. The SSH exec is the ships-dark Noop, so these tests assert the
 * AUTHORIZATION (which is real) and that the dark exec is reached ONLY after it passes.
 *
 * <p>Per the test-standard: USER (admin WITH a device license -> allowed), CROSS-USER (admin
 * WITHOUT a license -> denied; cross-domain device -> denied), MULTIUSER (a DOMAIN license
 * also authorizes).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DesktopRemoteInstallServiceTest {

    @Autowired DatabaseClient db;

    private static final String DEV_X = "dev-x-1";   // brandx, ADMIN-owned
    private static final String DEV_Y = "dev-y-1";   // brandy, ADMIN-owned
    private static final String DEV_S = "dev-s-1";   // brandx, SUPERADMIN-owned (core/primary)

    @BeforeEach
    void seed() {
        db.sql("DELETE FROM device_ssh_license").fetch().rowsUpdated().block();
        db.sql("DELETE FROM desktop_install_request").fetch().rowsUpdated().block();
        db.sql("DELETE FROM desktop_sudo_grant").fetch().rowsUpdated().block();
        db.sql("DELETE FROM desktop_app_catalog").fetch().rowsUpdated().block();
        db.sql("DELETE FROM device_registry").fetch().rowsUpdated().block();
        insertDevice(DEV_X, "fp-x", "brandx", "ADMIN");
        insertDevice(DEV_Y, "fp-y", "brandy", "ADMIN");
        insertDevice(DEV_S, "fp-s", "brandx", "SUPERADMIN");
        // enable an app ref in each domain so the catalog-allowlist leg passes when authorized.
        enableRef("brandx", "org.x.app");
        enableRef("brandy", "org.y.app");
    }

    private void insertDevice(String id, String fp, String domain, String ownerType) {
        db.sql("INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, domain, mesh_id) "
                        + "VALUES (:id, :fp, :h, :img, :ot, 'o', :domain, 'mesh-1')")
                .bind("id", id).bind("fp", fp).bind("h", id)
                .bind("img", "SUPERADMIN".equals(ownerType) ? "primary" : "client")
                .bind("ot", ownerType).bind("domain", domain)
                .fetch().rowsUpdated().block();
    }

    private void enableRef(String domain, String ref) {
        new DesktopAppCatalogRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.desktop.DesktopAppCatalogR2dbcRepository.class)).insert(domain, ref, ref, "FLATPAK", "a")
                .flatMap(e -> new DesktopAppCatalogRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.desktop.DesktopAppCatalogR2dbcRepository.class))
                        .setEnabled(e.id(), true, PrincipalDomain.superadminFor(domain)))
                .block();
    }

    private void grantDeviceLicense(String operator, String deviceId, String domain) {
        db.sql("INSERT INTO device_ssh_license "
                        + "(id, operator, scope_type, device_id, key_fingerprints, state, granted_by, "
                        + " domain, propagation_state, generation) "
                        + "VALUES (gen_random_uuid(), :op, 'DEVICE', :dev, 'SHA256:k', 'active', 'root', "
                        + " :domain, 'pending', 1)")
                .bind("op", operator).bind("dev", deviceId).bind("domain", domain)
                .fetch().rowsUpdated().block();
    }

    private void grantDomainLicense(String operator, String targetDomain) {
        db.sql("INSERT INTO device_ssh_license "
                        + "(id, operator, scope_type, target_domain, key_fingerprints, state, granted_by, "
                        + " domain, propagation_state, generation) "
                        + "VALUES (gen_random_uuid(), :op, 'DOMAIN', :td, 'SHA256:k', 'active', 'root', "
                        + " :td, 'pending', 1)")
                .bind("op", operator).bind("td", targetDomain)
                .fetch().rowsUpdated().block();
    }

    private DesktopRemoteInstallService service() {
        return new DesktopRemoteInstallService(new DeviceRegistryRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.device.DeviceRowRepository.class)),
                new SshLicenseRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.device.SshLicenseRowRepository.class)), new DesktopAppCatalogRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.desktop.DesktopAppCatalogR2dbcRepository.class)),
                new NoopDesktopSshClient());
    }

    // ── USER / MULTIUSER: admin WITH a license is allowed ────────────────────────

    @Nested
    class Allowed {
        @Test
        void adminWithActiveDeviceLicense_isAuthorized_thenDarkExec() {
            grantDeviceLicense("admin-x", DEV_X, "brandx");
            String out = service().remoteInstall("admin-x", DEV_X, "org.x.app",
                    PrincipalDomain.superadminFor("brandx")).block();
            assertThat(out).contains("\"dark\":true");   // exec reached only AFTER authz, ships dark
            assertThat(service().sshIsReal()).isFalse();
        }

        @Test
        void adminWithActiveDomainLicense_isAuthorized() {
            grantDomainLicense("admin-x", "brandx");
            String out = service().remoteInstall("admin-x", DEV_X, "org.x.app",
                    PrincipalDomain.superadminFor("brandx")).block();
            assertThat(out).contains("\"dark\":true");
        }
    }

    // ── CROSS-USER fail-closed DENY ──────────────────────────────────────────────

    @Nested
    class Denied {
        @Test
        void adminWithoutAnyLicenseForDevice_isDenied() {
            // no license row at all -> denied (fail-closed).
            StepVerifier.create(service().remoteInstall("admin-x", DEV_X, "org.x.app",
                            PrincipalDomain.superadminFor("brandx")))
                    .expectErrorMatches(e ->
                            e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException
                            && e.getMessage().contains("no active SSH license"))
                    .verify();
        }

        @Test
        void scopedAdmin_crossDomainDevice_isDenied_beforeLicenseCheck() {
            // a brandX-scoped admin targeting a brandY device -> denied (cross-domain wall),
            // even if they somehow held a license.
            PrincipalDomain brandXScope = scoped("brandx");
            StepVerifier.create(service().remoteInstall("admin-x", DEV_Y, "org.y.app", brandXScope))
                    .expectErrorMatches(e ->
                            e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException
                            && e.getMessage().contains("not in your domain"))
                    .verify();
        }

        @Test
        void deviceLicenseForWrongDevice_doesNotAuthorizeAnother() {
            // admin holds a DEVICE license for DEV_Y only; targeting DEV_X -> denied.
            grantDeviceLicense("admin-x", DEV_Y, "brandy");
            StepVerifier.create(service().remoteInstall("admin-x", DEV_X, "org.x.app",
                            PrincipalDomain.superadminFor("brandx")))
                    .expectErrorMatches(e ->
                            e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException)
                    .verify();
        }

        @Test
        void refNotEnabledInDomain_isDenied_evenWithLicense() {
            grantDeviceLicense("admin-x", DEV_X, "brandx");
            // ref not in brandx's enabled allowlist -> denied (the install target must be allowlisted).
            StepVerifier.create(service().remoteInstall("admin-x", DEV_X, "not.enabled.ref",
                            PrincipalDomain.superadminFor("brandx")))
                    .expectErrorMatches(e ->
                            e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException
                            && e.getMessage().contains("enabled Discover allowlist"))
                    .verify();
        }

        @Test
        void unregisteredDevice_isDenied() {
            StepVerifier.create(service().remoteInstall("admin-x", "ghost", "org.x.app",
                            PrincipalDomain.superadminFor("brandx")))
                    .expectErrorMatches(e ->
                            e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException
                            && e.getMessage().contains("not registered"))
                    .verify();
        }

        // ── FIX 2: SUPERADMIN-owned (core/primary) node guard ────────────────────

        @Test
        void remoteInstall_onSuperadminOwnedNode_isDenied_evenWithDomainLicense() {
            // admin-x holds a DOMAIN ssh-license on brandx (which holdsActiveLicense honours),
            // and the target core node is resident in brandx — without the superadmin-owned
            // guard the DOMAIN license would AUTHORIZE a core-node install. Must be DENIED.
            grantDomainLicense("admin-x", "brandx");
            enableRef("brandx", "org.s.app");
            StepVerifier.create(service().remoteInstall("admin-x", DEV_S, "org.s.app",
                            PrincipalDomain.superadminFor("brandx")))
                    .expectErrorMatches(e ->
                            e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException
                            && e.getMessage().contains("SUPERADMIN-owned node"))
                    .verify();
        }

        @Test
        void authorizeTerminal_onSuperadminOwnedNode_isDenied_evenWithDomainLicense() {
            grantDomainLicense("admin-x", "brandx");
            StepVerifier.create(service().authorizeTerminal("admin-x", DEV_S,
                            PrincipalDomain.superadminFor("brandx")))
                    .expectErrorMatches(e ->
                            e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException
                            && e.getMessage().contains("SUPERADMIN-owned node"))
                    .verify();
        }
    }

    // ── authorizeTerminal direct coverage (the SSH-terminal leg) ─────────────────

    @Nested
    class Terminal {
        @Test
        void withActiveDeviceLicense_completes() {
            grantDeviceLicense("admin-x", DEV_X, "brandx");
            StepVerifier.create(service().authorizeTerminal("admin-x", DEV_X,
                            PrincipalDomain.superadminFor("brandx")))
                    .verifyComplete();   // authorized -> empty completion (no app ref)
        }

        @Test
        void withoutLicense_isDenied() {
            StepVerifier.create(service().authorizeTerminal("admin-x", DEV_X,
                            PrincipalDomain.superadminFor("brandx")))
                    .expectErrorMatches(e ->
                            e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException
                            && e.getMessage().contains("no active SSH license"))
                    .verify();
        }

        @Test
        void crossDomain_isDenied() {
            // a brandX-scoped admin opening a terminal on a brandY device -> denied.
            StepVerifier.create(service().authorizeTerminal("admin-x", DEV_Y, scoped("brandx")))
                    .expectErrorMatches(e ->
                            e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException
                            && e.getMessage().contains("not in your domain"))
                    .verify();
        }
    }

    // ── BFF-RI: the onAuthorized (step-up consume) callback fires ONCE, only after full authz ──

    @Nested
    class StepUpConsumeCallback {
        @Test
        void onAuthorized_runsExactlyOnce_afterAuthzPasses() {
            grantDeviceLicense("admin-x", DEV_X, "brandx");
            java.util.concurrent.atomic.AtomicInteger consumed = new java.util.concurrent.atomic.AtomicInteger();
            service().remoteInstall("admin-x", DEV_X, "org.x.app",
                    PrincipalDomain.superadminFor("brandx"), consumed::incrementAndGet).block();
            assertThat(consumed.get()).isEqualTo(1);  // burned the single-use token exactly once
        }

        @Test
        void onAuthorized_neverRuns_whenDenied() {
            // no license -> denied -> the step-up token must NOT be consumed (a denied attempt does
            // not waste the operator's token).
            java.util.concurrent.atomic.AtomicInteger consumed = new java.util.concurrent.atomic.AtomicInteger();
            StepVerifier.create(service().remoteInstall("admin-x", DEV_X, "org.x.app",
                            PrincipalDomain.superadminFor("brandx"), consumed::incrementAndGet))
                    .expectError(DesktopRemoteInstallService.RemoteInstallDeniedException.class)
                    .verify();
            assertThat(consumed.get()).isZero();
        }

        @Test
        void onAuthorized_neverRuns_whenRefNotEnabled() {
            // authz device+license pass but the ref is not allowlisted -> denied BEFORE consume.
            grantDeviceLicense("admin-x", DEV_X, "brandx");
            java.util.concurrent.atomic.AtomicInteger consumed = new java.util.concurrent.atomic.AtomicInteger();
            StepVerifier.create(service().remoteInstall("admin-x", DEV_X, "not.enabled.ref",
                            PrincipalDomain.superadminFor("brandx"), consumed::incrementAndGet))
                    .expectError(DesktopRemoteInstallService.RemoteInstallDeniedException.class)
                    .verify();
            assertThat(consumed.get()).isZero();
        }
    }

    private static PrincipalDomain scoped(String domain) {
        // a non-superadmin scope homed at `domain` (scoped() == true) — build via a JWT.
        var jwt = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t")
                .header("alg", "none")
                .issuedAt(java.time.Instant.now()).expiresAt(java.time.Instant.now().plusSeconds(3600))
                .subject("admin-x").issuer("https://idp.brandx.example")
                .claim("roles", java.util.List.of("admin")).build();
        var auth = new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(
                jwt, java.util.List.of(
                        new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"),
                        new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
        var registry = new systems.hugmesh.commons.security.DomainRegistry("",
                "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
        return PrincipalDomain.of(auth, registry);
    }
}
