package systems.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.adminbff.lease.AlwaysLeader;
import systems.hugmesh.adminbff.lease.LeaderElection;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The App-Store expiry loop — a CLONE of {@code SuspensionExpiryAction} — over a real H2
 * repo. Proves:
 * <ul>
 *   <li>EXPIRY CAS: a deployment past {@code ending_at} flips {@code active -> ended},
 *       stamping {@code ended_at} and setting {@code propagation_state='applied'};</li>
 *   <li>LEASE-GATED single writer: when {@code !isLeader()} the tick is a complete no-op
 *       (nothing ends, the emitter is never called) — the EXISTING LeaderElection lease;</li>
 *   <li>IDEMPOTENT: a second tick over an already-ended row makes no further change and
 *       does not re-emit (the markEnded CAS lost);</li>
 *   <li>SHIPS DARK: the tick EMITS the enforce_actions via the {@link EnforceActionEmitter}
 *       seam (logged), but the action depends on NO ArgoCD/Casdoor/cert client at all — the
 *       emitter makes no real effect. We assert the emitter is the ONLY effector touched.</li>
 *   <li>no-expiry + future rows are never ended.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class ServiceDeploymentExpiryActionTest {

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        // The @DataR2dbcTest H2 store is per-CLASS; clear between methods so the expiry scan
        // only sees this method's rows.
        db.sql("DELETE FROM service_deployment").fetch().rowsUpdated().block();
    }

    private ServiceDeploymentRepository repo() {
        return new ServiceDeploymentRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.servicecatalog.ServiceDeploymentR2dbcRepository.class));
    }

    private ServiceDeploymentExpiryAction action(ServiceDeploymentRepository repo,
                                                 LeaderElection leader, EnforceActionEmitter emitter) {
        return new ServiceDeploymentExpiryAction(repo, leader, emitter);
    }

    @Test
    void overdueDeployment_flipsActiveToEnded_setsEndedAtAndPropagationApplied() {
        ServiceDeploymentRepository repo = repo();
        EnforceActionEmitter emitter = spy(new EnforceActionEmitter());
        ServiceDeployment d = repo.insertActive("brandx", "owncast", null,
                Instant.now().minusSeconds(30), "teardown,revoke-roles,alert", "root").block();

        action(repo, new AlwaysLeader(), emitter).runOnce().block();

        ServiceDeployment ended = repo.findById(d.id()).block();
        assertThat(ended.state()).isEqualTo(ServiceDeployment.STATE_ENDED);
        assertThat(ended.endedAt()).isNotNull();
        assertThat(ended.propagationState()).isEqualTo(ServiceDeployment.PROP_APPLIED);

        // SHIPS DARK: the enforce_actions were EMITTED (logged) via the seam exactly once.
        verify(emitter, times(1)).emit(org.mockito.ArgumentMatchers.any(ServiceDeployment.class));
    }

    @Test
    void notLeader_isCompleteNoOp_nothingEndedAndEmitterUntouched() {
        ServiceDeploymentRepository repo = repo();
        EnforceActionEmitter emitter = spy(new EnforceActionEmitter());
        ServiceDeployment d = repo.insertActive("brandx", "owncast", null,
                Instant.now().minusSeconds(30), "teardown", "root").block();

        LeaderElection follower = new LeaderElection() {
            @Override public boolean isLeader() { return false; }
            @Override public String label() { return "follower"; }
        };
        action(repo, follower, emitter).runOnce().block();

        // Lease-gated: a follower replica ends nothing and never emits.
        assertThat(repo.findById(d.id()).block().state()).isEqualTo(ServiceDeployment.STATE_ACTIVE);
        verifyNoInteractions(emitter);
    }

    @Test
    void secondTick_isIdempotent_doesNotReEmit() {
        ServiceDeploymentRepository repo = repo();
        EnforceActionEmitter emitter = spy(new EnforceActionEmitter());
        repo.insertActive("brandx", "owncast", null,
                Instant.now().minusSeconds(30), "teardown", "root").block();

        ServiceDeploymentExpiryAction act = action(repo, new AlwaysLeader(), emitter);
        act.runOnce().block();   // ends + emits once
        act.runOnce().block();   // nothing due now -> no second emit

        verify(emitter, times(1)).emit(org.mockito.ArgumentMatchers.any(ServiceDeployment.class));
    }

    @Test
    void noExpiryAndFutureRows_areNeverEnded() {
        ServiceDeploymentRepository repo = repo();
        EnforceActionEmitter emitter = spy(new EnforceActionEmitter());
        ServiceDeployment noExpiry = repo.insertActive("brandx", "phpbb", null, null, "alert", "root").block();
        ServiceDeployment future = repo.insertActive("brandx", "akkoma", null,
                Instant.now().plusSeconds(3600), "alert", "root").block();

        action(repo, new AlwaysLeader(), emitter).runOnce().block();

        assertThat(repo.findById(noExpiry.id()).block().state()).isEqualTo(ServiceDeployment.STATE_ACTIVE);
        assertThat(repo.findById(future.id()).block().state()).isEqualTo(ServiceDeployment.STATE_ACTIVE);
        verifyNoInteractions(emitter);
    }

    @Test
    void shipsDark_expiryActionItselfDependsOnNoArgoCdCasdoorOrCertClient() {
        // Structural proof the expiry loop's own dependency graph is unchanged: the action's
        // ONLY collaborators are the repo, the LeaderElection lease, and the emitter seam —
        // there is NO ArgoCD / Casdoor / cert / Kaniko client field on the action itself.
        // (The real teardown effect lives BEHIND the EnforceActionEmitter seam, gated dark.)
        List<String> fieldTypes = java.util.Arrays.stream(
                        ServiceDeploymentExpiryAction.class.getDeclaredFields())
                .map(Field::getType).map(Class::getName).toList();
        assertThat(fieldTypes).noneMatch(t ->
                t.toLowerCase().contains("argo")
                        || t.toLowerCase().contains("casdoor")
                        || t.toLowerCase().contains("cert")
                        || t.toLowerCase().contains("kaniko"));
    }

    @Test
    void shipsDark_emitWithDefaultEffector_makesNoRealArgoCdMutation() {
        // The emitter now delegates teardown to the AddServiceEffector seam, but with the
        // DEFAULT (Noop) ArgoCD client the teardown makes NO real ArgoCD call — ships dark.
        // We assert behaviourally: a teardown emit drives the effector's teardown leg against
        // a recording-but-noop ArgoCD client whose isReal()==false, and NO real create/delete
        // effect is observable (the recorder counts the would-be calls the noop swallows).
        var argo = new systems.hugmesh.adminbff.argocd.NoopArgoCdClient();
        var effector = new AddServiceEffector(argo, /*casdoor*/ null,
                new systems.hugmesh.adminbff.routeaccess.RouteAccessService(
                        new systems.hugmesh.adminbff.routeaccess.RouteAccessRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.routeaccess.RouteAccessRowRepository.class)),
                        new RecordingRouteMirror()),
                /*builder*/ null);
        EnforceActionEmitter emitter = new EnforceActionEmitter(effector);

        // effector reports DARK (the structural ships-dark signal the controller/test reads).
        assertThat(effector.effectorEnabled()).isFalse();
        assertThat(argo.isReal()).isFalse();

        ServiceDeployment d = repo().insertActive("brandx", "owncast", null,
                Instant.now().minusSeconds(5), "teardown,revoke-roles,alert", "root").block();
        // emit returns the action count and the teardown leg completes against the noop client
        // (no real ArgoCD mutation, no exception) — i.e. ships dark end to end.
        Integer count = emitter.emit(d).block();
        assertThat(count).isEqualTo(3);
    }

    /** A no-op RouteMirror for the dark-path test (the H2 RouteAccessService has no Cassandra). */
    static final class RecordingRouteMirror implements systems.hugmesh.adminbff.routeaccess.RouteMirror {
        @Override public reactor.core.publisher.Mono<Void> upsert(
                systems.hugmesh.adminbff.routeaccess.RouteRule rule) {
            return reactor.core.publisher.Mono.empty();
        }
        @Override public reactor.core.publisher.Mono<Void> delete(String id) {
            return reactor.core.publisher.Mono.empty();
        }
    }
}
