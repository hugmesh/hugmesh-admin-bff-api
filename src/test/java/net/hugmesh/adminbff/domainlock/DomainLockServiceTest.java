package net.hugmesh.adminbff.domainlock;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * The {@link DomainLockService} desired-state contract over a REAL H2 repository: lock
 * WRITES an active domain_lock row + triggers a reconcile tick + fires the synchronous
 * lock-immediacy enforce; a repeat lock is an idempotent no-op write; unlock CASes
 * active->removed + triggers a tick. The sync facade is mocked (the loop behaviour is
 * covered in DomainLockSyncActionTest); the homeserver is the gated stub-seam.
 */
@SpringBootTest(classes = DomainLockServiceTest.Boot.class)
@ActiveProfiles("test")
class DomainLockServiceTest extends AdminBffPostgresTestSupport {

    @org.springframework.boot.SpringBootConfiguration
    @org.springframework.boot.autoconfigure.EnableAutoConfiguration
    static class Boot { }

    @Autowired DatabaseClient db;

    // Clear domain_lock before each test (the H2 store is shared across methods in
    // this class) so listActive/activeByRole assertions see only this test's rows.
    @org.junit.jupiter.api.BeforeEach
    void clearTable() {
        db.sql("DELETE FROM domain_lock").fetch().rowsUpdated().block();
    }

    private DomainLockRepository repo() {
        return new DomainLockRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.domainlock.DomainLockRowRepository.class));
    }

    /** A brand-scoped ADMIN of the single-issuer "default" domain — so the scoped
     *  find/insert use {@code WHERE domain='default'}, matching the stamped row. */
    private static PrincipalDomain adminScope() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").claim("roles", List.of("admin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, new DomainRegistry("", ""));
    }

    @Test
    void lock_writesActiveRow_firesSynchronousEnforce_andTriggersTick() {
        DomainLockRepository repo = repo();
        DomainLockSyncActions actions = mock(DomainLockSyncActions.class);
        when(actions.triggerTick()).thenReturn(Mono.empty());
        // Spy the gated (stubbed) homeserver so we can assert the synchronous
        // lock-immediacy enforce fired (forceLocalMastodon(localpart, true)).
        HomeserverAdminClient homeserver = spy(new HomeserverAdminClient(null, null, false, false));

        DomainLockService svc = new DomainLockService(repo, actions, homeserver);
        DomainLock locked = svc.lock(DomainLock.ROLE_MASTODON_DOMAINLOCKED, "hugmesh/alice", "spam-federation", "admin", adminScope()).block();

        assertThat(locked).isNotNull();
        assertThat(locked.state()).isEqualTo("active");

        // The desired-state row is persisted (the active set IS the force-local allowlist).
        DomainLock found = repo.findActive("hugmesh/alice", DomainLock.ROLE_MASTODON_DOMAINLOCKED).block();
        assertThat(found).isNotNull();
        assertThat(found.localpart()).isEqualTo("alice");

        // LOCK-IMMEDIACY: the synchronous force-local enforce fired (no post-and-federate
        // window) and the reconcile tick was triggered.
        verify(homeserver, atLeastOnce()).forceLocalMastodon(eq("alice"), eq(true));
        verify(actions, atLeastOnce()).triggerTick();
    }

    @Test
    void lock_existingActive_isIdempotentNoOpWrite() {
        DomainLockRepository repo = repo();
        DomainLockSyncActions actions = mock(DomainLockSyncActions.class);
        when(actions.triggerTick()).thenReturn(Mono.empty());
        HomeserverAdminClient homeserver = new HomeserverAdminClient(null, null, false, false);

        DomainLockService svc = new DomainLockService(repo, actions, homeserver);
        DomainLock first = svc.lock(DomainLock.ROLE_MATRIX_DOMAINLOCKED, "hugmesh/bob", null, "admin", adminScope()).block();
        DomainLock second = svc.lock(DomainLock.ROLE_MATRIX_DOMAINLOCKED, "hugmesh/bob", null, "admin", adminScope()).block();

        // Same row id returned (no second active row inserted).
        assertThat(second.id()).isEqualTo(first.id());
        assertThat(repo.activeByRole(DomainLock.ROLE_MATRIX_DOMAINLOCKED).collectList().block())
                .hasSize(1);
    }

    @Test
    void unlock_casesActiveToRemoved_firesRelease_andTriggersTick() {
        DomainLockRepository repo = repo();
        DomainLockSyncActions actions = mock(DomainLockSyncActions.class);
        when(actions.triggerTick()).thenReturn(Mono.empty());
        HomeserverAdminClient homeserver = spy(new HomeserverAdminClient(null, null, false, false));

        DomainLockService svc = new DomainLockService(repo, actions, homeserver);
        svc.lock(DomainLock.ROLE_MASTODON_DOMAINLOCKED, "hugmesh/carol", null, "admin", adminScope()).block();

        svc.unlock(DomainLock.ROLE_MASTODON_DOMAINLOCKED, "hugmesh/carol", "admin", adminScope()).block();

        // The active row was CASed active->removed (reverse on unlock).
        assertThat(repo.findActive("hugmesh/carol", DomainLock.ROLE_MASTODON_DOMAINLOCKED).block())
                .isNull();
        // The synchronous release fired (forceLocalMastodon(localpart, false)).
        verify(homeserver, atLeastOnce()).forceLocalMastodon(eq("carol"), eq(false));
        // A tick is triggered on both lock and unlock.
        verify(actions, times(2)).triggerTick();
    }

    @Test
    void unlock_whenNotLocked_isNoOp() {
        DomainLockRepository repo = repo();
        DomainLockSyncActions actions = mock(DomainLockSyncActions.class);
        when(actions.triggerTick()).thenReturn(Mono.empty());
        HomeserverAdminClient homeserver = new HomeserverAdminClient(null, null, false, false);

        DomainLockService svc = new DomainLockService(repo, actions, homeserver);
        // No active lock for dave — unlock completes without error and triggers a tick.
        svc.unlock(DomainLock.ROLE_MATRIX_DOMAINLOCKED, "hugmesh/dave", "admin", adminScope()).block();
        assertThat(repo.findActive("hugmesh/dave", DomainLock.ROLE_MATRIX_DOMAINLOCKED).block())
                .isNull();
    }
}
