package net.hugmesh.adminbff.sshterminal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.desktop.terminal.DeviceTerminalDialProperties;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.DeviceRegistryCleanup;
import net.hugmesh.adminbff.support.DeviceRegistryCleanupConfig;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BFF-DIAL lifecycle keystone over a real Liquibase-applied H2 — proves the SUPERADMIN
 * {@code PENDING -> ACTIVE -> REVOKED} compare-and-swap + generation bump, the refuse-unpinned 422
 * precondition, the ships-dark activation refusal, idempotency, and the scoped-list cross-domain
 * isolation (ALLOW vs DENY). The verifying pinned test-connect is held-until-live.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, DeviceRegistryCleanupConfig.class})
@ActiveProfiles("test")
class DesktopDialServiceTest {

    @Autowired DatabaseClient db;

    @Autowired DeviceRegistryCleanup deviceRegistryCleanup;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM device_ssh_dial").fetch().rowsUpdated().block();
        deviceRegistryCleanup.clearDeviceRegistry().block();
    }

    private void seedDevice(String id, String domain) {
        db.sql("INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, "
                        + " domain, mesh_id, created_at) "
                        + "VALUES (:id, :fp, :h, 'primary', 'ADMIN', 'o', :domain, 'mesh-1', now())")
                .bind("id", id).bind("fp", "fp-" + id).bind("h", "node-" + id).bind("domain", domain)
                .fetch().rowsUpdated().block();
    }

    private DeviceSshDial pending(String deviceId, String hostKeyFp) {
        return pending(deviceId, hostKeyFp, "snapops");
    }

    private DeviceSshDial pending(String deviceId, String hostKeyFp, String dialUser) {
        return new DeviceSshDial(null, deviceId, dialUser, "ssh-ed25519 AAAA...", hostKeyFp,
                "SHA256:dialfp", "vault://kv/dial/" + deviceId, "dial-key-" + deviceId, null,
                DeviceSshDial.STATUS_PENDING, 1L, null, null);
    }

    private DeviceSshDialRepository repo() {
        return new DeviceSshDialRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.sshterminal.DeviceSshDialR2dbcRepository.class));
    }

    private DesktopDialService service(boolean dialEnabled) {
        DeviceTerminalDialProperties props = new DeviceTerminalDialProperties();
        props.setEnabled(dialEnabled);
        return new DesktopDialService(repo(), props);
    }

    // ── activate: PENDING -> ACTIVE + generation bump (dial flag ON) ─────────────

    @Nested
    class Activate {
        @Test
        void activatesPending_bumpsGeneration() {
            seedDevice("dev-1", "brandx");
            repo().insert(pending("dev-1", "SHA256:hostfp")).block();

            DeviceSshDial active = service(true).activate("dev-1", "super-1").block();
            assertThat(active.status()).isEqualTo(DeviceSshDial.STATUS_ACTIVE);
            assertThat(active.isActive()).isTrue();
            assertThat(active.generation()).isEqualTo(2L);   // bumped from 1
        }

        @Test
        void refusesUnpinnedRow_unprocessable() {
            seedDevice("dev-1", "brandx");
            // a PENDING row with a present-but-blank host_key_fp is rejected; insert one with a
            // single space (NOT NULL column) and assert refuse.
            repo().insert(pending("dev-1", " ")).block();
            StepVerifier.create(service(true).activate("dev-1", "super-1"))
                    .expectError(DesktopDialService.DialUnpinnedException.class)
                    .verify();
            // stays PENDING — never flipped.
            assertThat(repo().findByDeviceId("dev-1").block().status())
                    .isEqualTo(DeviceSshDial.STATUS_PENDING);
        }

        /** An MD5 pin is a 128-bit digest with practical collisions. The verifier still ACCEPTS one
         *  (rows seeded before the SHA-256 contract), so the refusal lives at activation — which is
         *  what keeps an MD5 pin from ever reaching a live dial. */
        @Test
        void refusesMd5Pin_neverBecomesActive() {
            seedDevice("dev-1", "brandx");
            repo().insert(pending("dev-1", "MD5:aa:bb:cc:dd")).block();
            StepVerifier.create(service(true).activate("dev-1", "super-1"))
                    .expectError(DesktopDialService.DialPolicyException.class)
                    .verify();
            assertThat(repo().findByDeviceId("dev-1").block().status())
                    .isEqualTo(DeviceSshDial.STATUS_PENDING);
        }

        /** A bare colon-hex pin carries no SHA256: label either — also refused. */
        @Test
        void refusesUnlabelledPin_neverBecomesActive() {
            seedDevice("dev-1", "brandx");
            repo().insert(pending("dev-1", "aa:bb:cc:dd")).block();
            StepVerifier.create(service(true).activate("dev-1", "super-1"))
                    .expectError(DesktopDialService.DialPolicyException.class)
                    .verify();
            assertThat(repo().findByDeviceId("dev-1").block().status())
                    .isEqualTo(DeviceSshDial.STATUS_PENDING);
        }

        /** dial_user comes from the image-build ingest. If it says root, activating would hand this
         *  control-plane pod a root shell on the device — refuse, and never flip the row. */
        @Test
        void refusesRootDialUser_neverBecomesActive() {
            seedDevice("dev-1", "brandx");
            repo().insert(pending("dev-1", "SHA256:hostfp", "root")).block();
            StepVerifier.create(service(true).activate("dev-1", "super-1"))
                    .expectError(DesktopDialService.DialPolicyException.class)
                    .verify();
            assertThat(repo().findByDeviceId("dev-1").block().status())
                    .isEqualTo(DeviceSshDial.STATUS_PENDING);
        }

        @Test
        void refusesRootDialUser_inAnyCasing() {
            seedDevice("dev-1", "brandx");
            repo().insert(pending("dev-1", "SHA256:hostfp", "ROOT")).block();
            StepVerifier.create(service(true).activate("dev-1", "super-1"))
                    .expectError(DesktopDialService.DialPolicyException.class)
                    .verify();
        }

        /** Non-vacuousness: a SHA256 pin with an ordinary non-root dial user still activates. */
        @Test
        void stillActivates_sha256PinAndNonRootDialUser() {
            seedDevice("dev-1", "brandx");
            repo().insert(pending("dev-1", "SHA256:hostfp", "rootless-ops")).block();
            assertThat(service(true).activate("dev-1", "super-1").block().status())
                    .isEqualTo(DeviceSshDial.STATUS_ACTIVE);
        }

        @Test
        void absentRow_notFound() {
            StepVerifier.create(service(true).activate("ghost", "super-1"))
                    .expectError(DesktopDialService.DialNotFoundException.class)
                    .verify();
        }

        @Test
        void doubleActivate_isIdempotentNoOp() {
            seedDevice("dev-1", "brandx");
            repo().insert(pending("dev-1", "SHA256:hostfp")).block();
            DeviceSshDial first = service(true).activate("dev-1", "super-1").block();
            DeviceSshDial again = service(true).activate("dev-1", "super-1").block();
            assertThat(again.status()).isEqualTo(DeviceSshDial.STATUS_ACTIVE);
            // generation did NOT bump again (the CAS guard requires status=PENDING).
            assertThat(again.generation()).isEqualTo(first.generation());
        }

        @Test
        void shipsDark_whenDialDisabled_503Refusal_neverFlips() {
            seedDevice("dev-1", "brandx");
            repo().insert(pending("dev-1", "SHA256:hostfp")).block();
            StepVerifier.create(service(false).activate("dev-1", "super-1"))
                    .expectError(DesktopDialService.DialDarkException.class)
                    .verify();
            assertThat(repo().findByDeviceId("dev-1").block().status())
                    .isEqualTo(DeviceSshDial.STATUS_PENDING);   // never activated while dark
        }
    }

    // ── revoke: ACTIVE -> REVOKED CAS + generation bump (allowed while dark) ─────

    @Nested
    class Revoke {
        @Test
        void revokesActive_bumpsGeneration_neverDeletes() {
            seedDevice("dev-1", "brandx");
            repo().insert(pending("dev-1", "SHA256:hostfp")).block();
            service(true).activate("dev-1", "super-1").block();   // -> ACTIVE gen 2

            DeviceSshDial revoked = service(true).revoke("dev-1", "super-1").block();
            assertThat(revoked.status()).isEqualTo(DeviceSshDial.STATUS_REVOKED);
            assertThat(revoked.generation()).isEqualTo(3L);
            // row still exists (audit trail) — not deleted.
            assertThat(repo().findByDeviceId("dev-1").block()).isNotNull();
        }

        @Test
        void revokeAllowedWhileDark() {
            seedDevice("dev-1", "brandx");
            repo().insert(pending("dev-1", "SHA256:hostfp")).block();
            // force ACTIVE via the low-level setter so we can test revoke under the dark service.
            DeviceSshDial seeded = repo().findByDeviceId("dev-1").block();
            repo().activate(seeded.id(), 2L).block();
            DeviceSshDial revoked = service(false).revoke("dev-1", "super-1").block();
            assertThat(revoked.status()).isEqualTo(DeviceSshDial.STATUS_REVOKED);
        }

        @Test
        void doubleRevoke_isIdempotentNoOp() {
            seedDevice("dev-1", "brandx");
            repo().insert(pending("dev-1", "SHA256:hostfp")).block();
            service(true).activate("dev-1", "super-1").block();
            DeviceSshDial first = service(true).revoke("dev-1", "super-1").block();
            DeviceSshDial again = service(true).revoke("dev-1", "super-1").block();
            assertThat(again.status()).isEqualTo(DeviceSshDial.STATUS_REVOKED);
            assertThat(again.generation()).isEqualTo(first.generation());   // no second bump
        }

        @Test
        void revokeAbsent_notFound() {
            StepVerifier.create(service(true).revoke("ghost", "super-1"))
                    .expectError(DesktopDialService.DialNotFoundException.class)
                    .verify();
        }
    }

    // ── scoped list cross-domain isolation (ALLOW vs DENY) ───────────────────────

    @Nested
    class ScopedList {
        @Test
        void scopedToBrandX_seesOnlyBrandXDeviceRows() {
            seedDevice("dev-x", "brandx");
            seedDevice("dev-y", "brandy");
            repo().insert(pending("dev-x", "SHA256:x")).block();
            repo().insert(pending("dev-y", "SHA256:y")).block();

            var brandX = service(true).list(scoped("brandx")).collectList().block();
            assertThat(brandX).hasSize(1);
            assertThat(brandX.get(0).deviceId()).isEqualTo("dev-x");   // brandY row NOT leaked
        }

        @Test
        void superadminUnscoped_seesAll() {
            seedDevice("dev-x", "brandx");
            seedDevice("dev-y", "brandy");
            repo().insert(pending("dev-x", "SHA256:x")).block();
            repo().insert(pending("dev-y", "SHA256:y")).block();

            var all = service(true).list(PrincipalDomain.superadminFor("brandx")).collectList().block();
            assertThat(all).hasSize(2);
        }
    }

    private static PrincipalDomain scoped(String domain) {
        var jwt = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t")
                .header("alg", "none")
                .issuedAt(java.time.Instant.now()).expiresAt(java.time.Instant.now().plusSeconds(3600))
                .subject("admin-x").issuer("https://idp." + domain + ".example")
                .claim("roles", java.util.List.of("admin")).build();
        var auth = new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(
                jwt, java.util.List.of(
                        new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
        var registry = new net.hugmesh.commons.security.DomainRegistry("",
                "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
        return PrincipalDomain.of(auth, registry);
    }
}
