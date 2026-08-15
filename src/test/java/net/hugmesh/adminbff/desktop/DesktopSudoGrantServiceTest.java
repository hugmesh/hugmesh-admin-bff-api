package net.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.SshLicenseRepository;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.DeviceRegistryCleanup;
import net.hugmesh.adminbff.support.DeviceRegistryCleanupConfig;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The DesktopSudoGrantService over a real H2 + DeviceRegistryRepository — proves the
 * device-resolved residency stamping, the SUPERADMIN-owned-device rejection, idempotent
 * grant, and the entitlement read (the IdP claim source). USER + MULTIUSER + CROSS-USER.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, DeviceRegistryCleanupConfig.class})
@ActiveProfiles("test")
class DesktopSudoGrantServiceTest {

    @Autowired DatabaseClient db;
    @Autowired DeviceRegistryCleanup deviceRegistryCleanup;

    private static final String DEV_ADMIN_OWNED = "dev-a";
    private static final String DEV_SUPER_OWNED = "dev-s";

    @BeforeEach
    void seed() {
        deviceRegistryCleanup.clearDeviceRegistry().block();
        insertDevice(DEV_ADMIN_OWNED, "fp-a", "brandx", "ADMIN");
        insertDevice(DEV_SUPER_OWNED, "fp-s", "brandx", "SUPERADMIN");
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

    private DesktopSudoGrantService service() {
        // The ships-dark default seam — rows honestly stay 'pending' (no IdP write).
        return service(new NoopDesktopSudoClaimSync());
    }

    private DesktopSudoGrantService service(DesktopSudoClaimSync claimSync) {
        return new DesktopSudoGrantService(new DesktopSudoGrantRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.desktop.DesktopSudoGrantR2dbcRepository.class)),
                new DeviceRegistryRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.device.DeviceRowRepository.class)), new SshLicenseRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.device.SshLicenseRowRepository.class)),
                claimSync);
    }

    /** A scripted claim-sync seam: records every pushed row and returns the scripted outcome. */
    private static final class ScriptedClaimSync implements DesktopSudoClaimSync {
        final java.util.List<DesktopSudoGrant> pushed = new java.util.ArrayList<>();
        private final java.util.function.Function<DesktopSudoGrant, reactor.core.publisher.Mono<String>> outcome;
        ScriptedClaimSync(java.util.function.Function<DesktopSudoGrant, reactor.core.publisher.Mono<String>> outcome) {
            this.outcome = outcome;
        }
        @Override public reactor.core.publisher.Mono<String> propagate(DesktopSudoGrant grant) {
            pushed.add(grant);
            return outcome.apply(grant);
        }
        @Override public boolean isReal() { return true; }
    }

    /** The persisted {@code propagation_state} for one grant row. */
    private String propagationStateInDb(String id) {
        return db.sql("SELECT propagation_state FROM desktop_sudo_grant WHERE id = :id")
                .bind("id", id).map(r -> r.get(0, String.class)).one().block();
    }

    /** Seed an ACTIVE DEVICE ssh-license for the operator on a device (mirrors the
     *  DesktopRemoteInstallServiceTest idiom — sudo-grant now also requires one). */
    private void grantDeviceLicense(String operator, String deviceId, String domain) {
        db.sql("INSERT INTO device_ssh_license "
                        + "(id, operator, scope_type, device_id, key_fingerprints, state, granted_by, "
                        + " domain, propagation_state, generation) "
                        + "VALUES (gen_random_uuid(), :op, 'DEVICE', :dev, 'SHA256:k', 'active', 'root', "
                        + " :domain, 'pending', 1)")
                .bind("op", operator).bind("dev", deviceId).bind("domain", domain)
                .fetch().rowsUpdated().block();
    }

    /** Seed an ACTIVE DOMAIN ssh-license for the operator on a residency domain. */
    private void grantDomainLicense(String operator, String targetDomain) {
        db.sql("INSERT INTO device_ssh_license "
                        + "(id, operator, scope_type, target_domain, key_fingerprints, state, granted_by, "
                        + " domain, propagation_state, generation) "
                        + "VALUES (gen_random_uuid(), :op, 'DOMAIN', :td, 'SHA256:k', 'active', 'root', "
                        + " :td, 'pending', 1)")
                .bind("op", operator).bind("td", targetDomain)
                .fetch().rowsUpdated().block();
    }

    /** A SUPERADMIN (unscoped) acting scope — the happy path used by the legacy tests. */
    private static PrincipalDomain superadmin() {
        return PrincipalDomain.superadminFor("brandx");
    }

    @Test
    void grant_stampsDeviceResidencyDomain() {
        grantDeviceLicense("root", DEV_ADMIN_OWNED, "brandx");   // grant now requires an active ssh-license
        DesktopSudoGrant g = service().grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        assertThat(g.domain()).isEqualTo("brandx");      // from the device, not the caller
        assertThat(g.isActive()).isTrue();
    }

    @Test
    void grant_isIdempotent() {
        grantDeviceLicense("root", DEV_ADMIN_OWNED, "brandx");
        DesktopSudoGrantService s = service();
        DesktopSudoGrant first = s.grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        DesktopSudoGrant second = s.grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        assertThat(second.id()).isEqualTo(first.id());   // no-op grant returns the same row
    }

    @Test
    void grant_onSuperadminOwnedDevice_isRejected() {
        StepVerifier.create(service().grant("alice", DEV_SUPER_OWNED, "root", superadmin()))
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().contains("SUPERADMIN-owned"))
                .verify();
    }

    @Test
    void grant_onUnregisteredDevice_isRejected() {
        StepVerifier.create(service().grant("alice", "ghost", "root", superadmin()))
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().contains("not registered"))
                .verify();
    }

    @Test
    void entitlement_isActiveAfterGrant_noneAfterRevoke() {
        grantDeviceLicense("root", DEV_ADMIN_OWNED, "brandx");
        DesktopSudoGrantService s = service();
        DesktopSudoGrant g = s.grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        assertThat(s.entitlement("alice", DEV_ADMIN_OWNED).block()).isNotNull();
        // revoked grant -> entitlement none (the keystone for centrally-revocable sudo).
        assertThat(s.revoke(g.id(), "root", PrincipalDomain.superadminFor("brandx")).block()).isEqualTo(1L);
        StepVerifier.create(s.entitlement("alice", DEV_ADMIN_OWNED)).verifyComplete();
    }

    // ── CROSS-DOMAIN own-domain wall (FIX 1) ─────────────────────────────────────

    @Test
    void sameDomainAdmin_canGrantOnOwnBrandDevice() {
        // a brandX-scoped admin granting on a brandX device -> allowed (own-domain) when they
        // also hold an active ssh-license for the device (the new precondition).
        grantDeviceLicense("admin-x", DEV_ADMIN_OWNED, "brandx");
        DesktopSudoGrant g = service().grant("alice", DEV_ADMIN_OWNED, "admin-x", scoped("brandx")).block();
        assertThat(g).isNotNull();
        assertThat(g.domain()).isEqualTo("brandx");
        assertThat(g.isActive()).isTrue();
    }

    @Test
    void scopedAdmin_cannotGrantOnOtherBrandDevice() {
        // a brandX-scoped admin granting on a brandY device -> DENIED (cross-domain wall),
        // mirroring DesktopRemoteInstallServiceTest.scopedAdmin_crossDomainDevice_isDenied_*.
        insertDevice("dev-y", "fp-y", "brandy", "ADMIN");
        StepVerifier.create(service().grant("alice", "dev-y", "admin-x", scoped("brandx")))
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().contains("not in your domain"))
                .verify();
    }

    // ── device-ssh-license precondition (product-decision RESOLVED) ──────────────
    //   parity with DesktopRemoteInstallService.remoteInstall's holdsActiveLicense:
    //   an own-domain admin must ALSO hold an active DEVICE/DOMAIN ssh-license for the
    //   target device, else the grant is DENIED (RemoteInstallDeniedException -> 403).

    @Test
    void grant_withoutActiveSshLicenseForDevice_isDenied() {
        // FAIL-FIRST: an own-domain admin with NO active ssh-license for the device. Before
        // this change the grant SUCCEEDED (returned a brandx row); now it must be DENIED.
        StepVerifier.create(service().grant("alice", DEV_ADMIN_OWNED, "admin-x", scoped("brandx")))
                .expectErrorMatches(e ->
                        e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException
                        && e.getMessage().contains("no active SSH license"))
                .verify();
    }

    @Test
    void grant_withActiveDeviceSshLicense_succeeds() {
        // a DEVICE license on THIS device authorizes the grant.
        grantDeviceLicense("admin-x", DEV_ADMIN_OWNED, "brandx");
        DesktopSudoGrant g = service().grant("alice", DEV_ADMIN_OWNED, "admin-x", scoped("brandx")).block();
        assertThat(g).isNotNull();
        assertThat(g.domain()).isEqualTo("brandx");
        assertThat(g.isActive()).isTrue();
    }

    @Test
    void grant_withActiveDomainSshLicense_succeeds() {
        // a DOMAIN license on the device's residency also authorizes (same semantics as
        // holdsActiveLicense in remote-install).
        grantDomainLicense("admin-x", "brandx");
        DesktopSudoGrant g = service().grant("alice", DEV_ADMIN_OWNED, "admin-x", scoped("brandx")).block();
        assertThat(g).isNotNull();
        assertThat(g.isActive()).isTrue();
    }

    @Test
    void grant_withDeviceLicenseForWrongDevice_isDenied() {
        // a DEVICE license for a DIFFERENT device does not authorize the target device.
        insertDevice("dev-other", "fp-o", "brandx", "ADMIN");
        grantDeviceLicense("admin-x", "dev-other", "brandx");
        StepVerifier.create(service().grant("alice", DEV_ADMIN_OWNED, "admin-x", scoped("brandx")))
                .expectErrorMatches(e ->
                        e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException
                        && e.getMessage().contains("no active SSH license"))
                .verify();
    }

    @Test
    void grant_asSuperadmin_withoutActiveSshLicense_isDenied() {
        // remote-install runs holdsActiveLicense for EVERY role (only the cross-domain wall is
        // superadmin-exempt via scope.scoped()); mirrored here — a SUPERADMIN with no active
        // license is DENIED too, NOT exempt.
        StepVerifier.create(service().grant("alice", DEV_ADMIN_OWNED, "root", superadmin()))
                .expectErrorMatches(e ->
                        e instanceof DesktopRemoteInstallService.RemoteInstallDeniedException
                        && e.getMessage().contains("no active SSH license"))
                .verify();
    }

    @Test
    void grant_asSuperadmin_withActiveLicense_succeeds() {
        // and with an active license, the SUPERADMIN grant proceeds (the license is required,
        // not the cross-domain wall, for a superadmin).
        grantDeviceLicense("root", DEV_ADMIN_OWNED, "brandx");
        DesktopSudoGrant g = service().grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        assertThat(g).isNotNull();
        assertThat(g.isActive()).isTrue();
    }

    // ── IdP claim propagation (the Casdoor desktop-sudo role sync seam) ──────────

    @Test
    void grant_pushesActiveRowThroughClaimSync_andStampsApplied() {
        grantDeviceLicense("root", DEV_ADMIN_OWNED, "brandx");
        ScriptedClaimSync sync = new ScriptedClaimSync(
                g -> reactor.core.publisher.Mono.just(DesktopSudoGrant.PROP_APPLIED));
        DesktopSudoGrant g = service(sync).grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        // The seam saw the fresh ACTIVE row (the add-membership direction) …
        assertThat(sync.pushed).hasSize(1);
        assertThat(sync.pushed.get(0).subject()).isEqualTo("alice");
        assertThat(sync.pushed.get(0).isActive()).isTrue();
        // … and the applied outcome is stamped on the row (returned AND persisted).
        assertThat(g.propagationState()).isEqualTo(DesktopSudoGrant.PROP_APPLIED);
        assertThat(propagationStateInDb(g.id())).isEqualTo(DesktopSudoGrant.PROP_APPLIED);
    }

    @Test
    void grant_leverOff_noopSync_leavesRowHonestlyPending() {
        // The ships-dark default (app.desktop.sudo.claim-sync.enabled=false -> Noop): no IdP
        // write happens, so the row must NOT claim propagation — it stays 'pending'.
        grantDeviceLicense("root", DEV_ADMIN_OWNED, "brandx");
        DesktopSudoGrant g = service(new NoopDesktopSudoClaimSync())
                .grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        assertThat(g.propagationState()).isEqualTo(DesktopSudoGrant.PROP_PENDING);
        assertThat(propagationStateInDb(g.id())).isEqualTo(DesktopSudoGrant.PROP_PENDING);
    }

    @Test
    void grant_syncFailure_stillGrants_rowStampedFailedForRetry() {
        // A Casdoor failure NEVER fails the grant — the row is authoritative; 'failed' is
        // stamped so the reconciler sweep retries it.
        grantDeviceLicense("root", DEV_ADMIN_OWNED, "brandx");
        ScriptedClaimSync sync = new ScriptedClaimSync(
                g -> reactor.core.publisher.Mono.just(DesktopSudoGrant.PROP_FAILED));
        DesktopSudoGrant g = service(sync).grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        assertThat(g).isNotNull();
        assertThat(g.isActive()).isTrue();
        assertThat(propagationStateInDb(g.id())).isEqualTo(DesktopSudoGrant.PROP_FAILED);
    }

    @Test
    void grant_seamContractViolation_errorIsSwallowed_grantStillSucceeds() {
        // propagate() NEVER errors by contract — but if a seam violates it, the mutate must
        // still succeed (best-effort push) and the row stays 'pending' for the sweep.
        grantDeviceLicense("root", DEV_ADMIN_OWNED, "brandx");
        ScriptedClaimSync sync = new ScriptedClaimSync(
                g -> reactor.core.publisher.Mono.error(new IllegalStateException("boom")));
        DesktopSudoGrant g = service(sync).grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        assertThat(g).isNotNull();
        assertThat(g.isActive()).isTrue();
        assertThat(propagationStateInDb(g.id())).isEqualTo(DesktopSudoGrant.PROP_PENDING);
    }

    @Test
    void grant_noOpOnExistingActive_doesNotRePush() {
        grantDeviceLicense("root", DEV_ADMIN_OWNED, "brandx");
        ScriptedClaimSync sync = new ScriptedClaimSync(
                g -> reactor.core.publisher.Mono.just(DesktopSudoGrant.PROP_APPLIED));
        DesktopSudoGrantService s = service(sync);
        s.grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        s.grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        // only the INSERT pushed; the idempotent no-op grant did not re-dial the IdP.
        assertThat(sync.pushed).hasSize(1);
    }

    @Test
    void revoke_pushesRevokedRow_pendingToApplied() {
        grantDeviceLicense("root", DEV_ADMIN_OWNED, "brandx");
        ScriptedClaimSync sync = new ScriptedClaimSync(
                g -> reactor.core.publisher.Mono.just(DesktopSudoGrant.PROP_APPLIED));
        DesktopSudoGrantService s = service(sync);
        DesktopSudoGrant g = s.grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        assertThat(s.revoke(g.id(), "root", superadmin()).block()).isEqualTo(1L);
        // The seam saw the POST-CAS row (state=revoked — the remove-membership direction) …
        assertThat(sync.pushed).hasSize(2);
        DesktopSudoGrant seen = sync.pushed.get(1);
        assertThat(seen.id()).isEqualTo(g.id());
        assertThat(seen.isActive()).isFalse();
        // … and the CAS-armed 'pending' was driven to 'applied'.
        assertThat(propagationStateInDb(g.id())).isEqualTo(DesktopSudoGrant.PROP_APPLIED);
    }

    @Test
    void revoke_casLoser_doesNotPush() {
        grantDeviceLicense("root", DEV_ADMIN_OWNED, "brandx");
        ScriptedClaimSync sync = new ScriptedClaimSync(
                g -> reactor.core.publisher.Mono.just(DesktopSudoGrant.PROP_APPLIED));
        DesktopSudoGrantService s = service(sync);
        DesktopSudoGrant g = s.grant("alice", DEV_ADMIN_OWNED, "root", superadmin()).block();
        assertThat(s.revoke(g.id(), "root", superadmin()).block()).isEqualTo(1L);
        // Second revoke loses the CAS (rows=0) — no second removal push.
        assertThat(s.revoke(g.id(), "root", superadmin()).block()).isEqualTo(0L);
        assertThat(sync.pushed).hasSize(2); // grant + first revoke only
    }

    /** A NON-superadmin scope homed at {@code domain} (scoped() == true), built from a JWT. */
    private static PrincipalDomain scoped(String domain) {
        var jwt = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t")
                .header("alg", "none")
                .issuedAt(java.time.Instant.now()).expiresAt(java.time.Instant.now().plusSeconds(3600))
                .subject("admin-x").issuer("https://idp." + domain + ".example")
                .claim("roles", java.util.List.of("admin")).build();
        var auth = new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(
                jwt, java.util.List.of(
                        new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"),
                        new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
        var registry = new net.hugmesh.commons.security.DomainRegistry("",
                "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");
        return PrincipalDomain.of(auth, registry);
    }
}
