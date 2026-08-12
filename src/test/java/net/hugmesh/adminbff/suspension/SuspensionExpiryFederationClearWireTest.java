package net.hugmesh.adminbff.suspension;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.federation.FederationOverrideClearClient;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.lease.AlwaysLeader;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * Wire test for the federation-override RESTORE leg of {@link SuspensionExpiryAction}:
 * when a PROFILE-scope timed suspension expires, the action calls
 * {@link FederationOverrideClearClient#clearSource} with the EXACT source tag
 * {@code access_suspension:<id>} (the tag the federation {@code scope=user} kill
 * override was written with), re-arming the suspended owner's modules; and that this
 * leg fires ONLY at PROFILE-scope expiry — never for a platform-role
 * (ROLE_MATRIX / ROLE_MASTODON) restore.
 *
 * <p>Uses a REAL H2 repository (from {@link TestDatabaseConfig}), a stubbed
 * {@link HomeserverAdminClient} (enabled=false), {@link AlwaysLeader}, a MOCKED
 * {@link GatewayRevocationClient}, and a MOCKED {@link FederationOverrideClearClient}
 * to capture the call. Mirrors {@code BanRevocationWireTest}.
 *
 * <p>Delineated:
 * <ul>
 *   <li>USER-SITUATIONAL: PROFILE-scope expiry calls
 *       {@code clearSource("access_suspension:<id>")} with the row's id;</li>
 *   <li>USER-SITUATIONAL: ROLE_MATRIX restore does NOT call clearSource (no override);</li>
 *   <li>USER-SITUATIONAL: ROLE_MASTODON restore does NOT call clearSource (no override);</li>
 *   <li>USER-SITUATIONAL: a PERMANENT PROFILE ban (expires_at NULL, restore_role=false)
 *       is excluded from dueForRestore and never calls clearSource.</li>
 * </ul>
 */
@SpringBootTest(classes = SuspensionExpiryFederationClearWireTest.Boot.class)
@ActiveProfiles("test")
class SuspensionExpiryFederationClearWireTest extends AdminBffPostgresTestSupport {

    @org.springframework.boot.SpringBootConfiguration
    @org.springframework.boot.autoconfigure.EnableAutoConfiguration
    static class Boot { }

    @Autowired DatabaseClient db;

    private final HomeserverAdminClient stubbedHomeserver =
            new HomeserverAdminClient(null, null, false);
    private final AlwaysLeader leader = new AlwaysLeader();

    @BeforeEach
    void clearTable() {
        db.sql("DELETE FROM access_suspension").fetch().rowsUpdated().block();
    }

    private AccessSuspensionRepository repo() {
        return new AccessSuspensionRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(
                db, net.hugmesh.adminbff.suspension.AccessSuspensionRowRepository.class));
    }

    private GatewayRevocationClient mockGateway() {
        GatewayRevocationClient mock = mock(GatewayRevocationClient.class);
        when(mock.clearCoarse(anyString(), anyString())).thenReturn(Mono.empty());
        when(mock.revokeCoarse(anyString(), anyString(), anyString(), anyLong())).thenReturn(Mono.empty());
        return mock;
    }

    private FederationOverrideClearClient mockFederationClear() {
        FederationOverrideClearClient mock = mock(FederationOverrideClearClient.class);
        when(mock.clearSource(anyString())).thenReturn(Mono.empty());
        return mock;
    }

    @Test
    void profile_expiry_calls_clearSource_with_access_suspension_source_tag() {
        AccessSuspensionRepository repo = repo();
        AccessSuspension row = repo.insertActive("hugmesh/grace", "grace",
                AccessSuspension.ROLE_PROFILE,
                Instant.now().minus(1, ChronoUnit.MINUTES), true, "timeout", "mod", "default").block();

        GatewayRevocationClient gateway = mockGateway();
        FederationOverrideClearClient federation = mockFederationClear();
        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(null, stubbedHomeserver, repo, leader, gateway, federation);
        expiry.runOnce().block();

        // The clear is BY SOURCE with the globally-unique row id — exactly the tag the
        // federation scope=user override was written with.
        verify(federation, atLeastOnce()).clearSource(eq("access_suspension:" + row.id()));
        // PROFILE has no coarse homeserver revocation key.
        verify(gateway, never()).clearCoarse(anyString(), anyString());
    }

    @Test
    void matrix_restore_never_calls_clearSource() {
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/heidi", "heidi",
                AccessSuspension.ROLE_MATRIX,
                Instant.now().minus(1, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        FederationOverrideClearClient federation = mockFederationClear();
        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(null, stubbedHomeserver, repo, leader, mockGateway(), federation);
        expiry.runOnce().block();

        verify(federation, never()).clearSource(anyString());
    }

    @Test
    void mastodon_restore_never_calls_clearSource() {
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/ivan", "ivan",
                AccessSuspension.ROLE_MASTODON,
                Instant.now().minus(1, ChronoUnit.MINUTES), true, null, "admin", "default").block();

        FederationOverrideClearClient federation = mockFederationClear();
        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(null, stubbedHomeserver, repo, leader, mockGateway(), federation);
        expiry.runOnce().block();

        verify(federation, never()).clearSource(anyString());
    }

    @Test
    void permanentProfileBan_never_calls_clearSource() {
        // Permanent PROFILE ban (expires_at NULL, restore_role=false) — excluded from
        // dueForRestore, so the expiry action never runs the restore legs for it.
        AccessSuspensionRepository repo = repo();
        repo.insertActive("hugmesh/judy", "judy",
                AccessSuspension.ROLE_PROFILE, null, false, "permanent", "admin", "default").block();

        FederationOverrideClearClient federation = mockFederationClear();
        SuspensionExpiryAction expiry =
                new SuspensionExpiryAction(null, stubbedHomeserver, repo, leader, mockGateway(), federation);
        expiry.runOnce().block();

        verify(federation, never()).clearSource(anyString());
    }
}
