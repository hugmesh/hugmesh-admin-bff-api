package net.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.routeaccess.RouteAccessRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessRowRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.adminbff.routeaccess.RouteRule;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;
import net.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The RECORD {@link AddServiceEffector} keeps of the route-access rows it writes
 * ({@code service_deployment_route_rule}), read back from the real table, and the guarantees
 * that depend on it:
 * <ul>
 *   <li>one record per written rule, stamped (never deleted) when the rule is removed;</li>
 *   <li>ATOMIC: a rule is never left without its record. If recording fails part-way, the
 *       rules already written in that provision are rolled back with it and nothing further
 *       runs — on a first provision and on a re-provision, which then keeps its earlier set;</li>
 *   <li>a re-provision writes its new rules before it removes the ones it replaces;</li>
 *   <li>a recorded id can only remove a rule of the deployment's OWN brand;</li>
 *   <li>a recorded rule an admin already deleted by hand does not block teardown;</li>
 *   <li>a deployment without an id is refused before anything is written.</li>
 * </ul>
 * Which rules survive a teardown is {@code AddServiceEffectorRecordedRulesTest}.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class AddServiceEffectorRuleRecordTest {

    private static final String BRAND = "acme.test";
    private static final String GW = "acme-test-be-gateway";

    /** 3 patterns x 2 roles once de-duplicated against the derived values. */
    private static final String FULL_PROFILE = "{"
            + "\"roles\":[\"ROLE_ADMIN\",\"ROLE_OWNCAST\"],"
            + "\"exposure\":{\"routes\":[\"/api/owncast/\",\"/api/owncast/**\",\"/ws/owncast/**\"],"
            + "\"mfaRequired\":true}}";

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        EffectorFixture.clear(db);
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────

    /** One row of the record table. */
    record Recorded(String ruleId, String deploymentId, boolean removed) {
    }

    private List<Recorded> records() {
        return db.sql("SELECT rule_id, deployment_id, removed_at FROM service_deployment_route_rule"
                        + " ORDER BY rule_id")
                .map((row, meta) -> new Recorded(
                        row.get("rule_id", UUID.class).toString(),
                        row.get("deployment_id", String.class),
                        row.get("removed_at") != null))
                .all().collectList().block();
    }

    private Set<String> recordedIds(boolean removed) {
        Set<String> out = new TreeSet<>();
        records().stream().filter(r -> r.removed() == removed).forEach(r -> out.add(r.ruleId()));
        return out;
    }

    private Set<String> ruleIds() {
        Set<String> out = new TreeSet<>();
        new RouteAccessRepository(R2dbcRepos.of(db, RouteAccessRowRepository.class))
                .list().collectList().block().forEach(r -> out.add(r.id()));
        return out;
    }

    private static ServiceDeployment deployment(String id, String profileRef) {
        return new ServiceDeployment(id, BRAND, "owncast", profileRef,
                ServiceDeployment.STATE_ACTIVE, Instant.now(), null, "teardown",
                ServiceDeployment.PROP_PENDING, null, "root");
    }

    private static ServiceSource source() {
        return new ServiceSource(ServiceSource.Kind.GIT, "https://forgejo/acme/owncast", "deploy/", "HEAD");
    }

    private static AppProfileRepository fullProfile() {
        AppProfileRepository profiles = mock(AppProfileRepository.class);
        when(profiles.findByName("streaming")).thenReturn(Mono.just(
                new AppProfile("p-1", "streaming", FULL_PROFILE, "root", Instant.now(), Instant.now())));
        return profiles;
    }

    private AddServiceEffector effector(net.hugmesh.adminbff.argocd.ArgoCdClient argo, AppProfileRepository profiles) {
        return EffectorFixture.effector(db, argo, EffectorFixture.routeAccess(db), null, profiles);
    }

    /**
     * An ArgoCD client that records a create when the returned Mono is SUBSCRIBED, the moment
     * the real {@code RestArgoCdClient} sends its request. The effector calls
     * {@code createApplication} while it assembles its chain, so a double that records at call
     * time ({@link AddServiceEffectorTest.RecordingArgoCd}) cannot tell whether the request
     * would ever have been made.
     */
    static final class SubscribedArgoCd implements net.hugmesh.adminbff.argocd.ArgoCdClient {
        final List<String> requested = new java.util.ArrayList<>();

        @Override
        public Mono<String> createApplication(String name, String repoUrl, String path,
                                              String targetRevision, String destNamespace) {
            return Mono.fromSupplier(() -> {
                requested.add(name);
                return name;
            });
        }

        @Override
        public Mono<Boolean> deleteApplication(String name) {
            return Mono.just(true);
        }

        @Override
        public boolean isReal() {
            return false;
        }
    }

    /** The real store, except that the {@code failAt}-th {@code record} call (1-based) fails. */
    static final class FailingRecords extends DeploymentRouteRuleRepository {
        private final int failAt;
        private int calls;

        FailingRecords(DatabaseClient db, int failAt) {
            super(R2dbcRepos.of(db, DeploymentRouteRuleR2dbcRepository.class));
            this.failAt = failAt;
        }

        @Override
        public Mono<Void> record(String deploymentId, String ruleId) {
            return Mono.defer(() -> ++calls == failAt
                    ? Mono.<Void>error(new IllegalStateException("record store down"))
                    : super.record(deploymentId, ruleId));
        }
    }

    private AddServiceEffector effectorWhoseRecordFails(net.hugmesh.adminbff.argocd.ArgoCdClient argo, int failAt) {
        return new AddServiceEffector(argo, null, EffectorFixture.routeAccess(db), null, fullProfile(),
                new FailingRecords(db, failAt), EffectorFixture.tx(db));
    }

    // ── one record per written rule ──────────────────────────────────────────────────

    @Test
    void provision_recordsEveryRuleItWrites_againstTheDeployment() {
        AddServiceEffector effector = effector(new AddServiceEffectorTest.RecordingArgoCd(), fullProfile());

        effector.provision(deployment("dep-owncast", "streaming"), source()).block();

        assertThat(ruleIds()).hasSize(6);
        assertThat(records()).hasSize(6)
                .allSatisfy(r -> {
                    assertThat(r.deploymentId()).isEqualTo("dep-owncast");
                    assertThat(r.removed()).isFalse();
                });
        assertThat(recordedIds(false)).isEqualTo(ruleIds());
    }

    @Test
    void teardown_removesTheRules_andStampsTheirRecordsWithoutDeletingThem() {
        AddServiceEffector effector = effector(new AddServiceEffectorTest.RecordingArgoCd(), fullProfile());
        ServiceDeployment d = deployment("dep-owncast", "streaming");
        effector.provision(d, source()).block();
        Set<String> written = ruleIds();

        effector.teardown(d).block();

        assertThat(ruleIds()).isEmpty();
        assertThat(recordedIds(true)).isEqualTo(written);   // all six kept, all six stamped
        assertThat(recordedIds(false)).isEmpty();
    }

    @Test
    void provisioningAgain_recordsTheNewRules_andStampsTheOnesItReplaced() {
        AddServiceEffector effector = effector(new AddServiceEffectorTest.RecordingArgoCd(), fullProfile());
        ServiceDeployment d = deployment("dep-owncast", "streaming");
        effector.provision(d, source()).block();
        Set<String> first = ruleIds();

        effector.provision(d, source()).block();

        Set<String> second = ruleIds();
        assertThat(second).hasSize(6).doesNotContainAnyElementsOf(first);
        assertThat(recordedIds(false)).isEqualTo(second);
        assertThat(recordedIds(true)).isEqualTo(first);
    }

    /** A mirror that only notes the order of the calls it receives. */
    static final class OrderedMirror implements net.hugmesh.adminbff.routeaccess.RouteMirror {
        final List<String> calls = new java.util.ArrayList<>();

        @Override
        public Mono<Void> upsert(RouteRule rule) {
            return Mono.fromRunnable(() -> calls.add("upsert " + rule.id()));
        }

        @Override
        public Mono<Void> delete(String id) {
            return Mono.fromRunnable(() -> calls.add("delete " + id));
        }
    }

    @Test
    void provisioningAgain_writesTheNewRulesBeforeItRemovesTheOnesItReplaces() {
        // The gateways poll the mirror, and the mirror is written outside the transaction: if
        // the old rules went first, they would see the deployment with no grants in between.
        OrderedMirror mirror = new OrderedMirror();
        RouteAccessService ra = new RouteAccessService(
                new RouteAccessRepository(R2dbcRepos.of(db, RouteAccessRowRepository.class)), mirror);
        AddServiceEffector effector = EffectorFixture.effector(db,
                new AddServiceEffectorTest.RecordingArgoCd(), ra, null, fullProfile());
        ServiceDeployment d = deployment("dep-owncast", "streaming");
        effector.provision(d, source()).block();
        Set<String> first = ruleIds();
        mirror.calls.clear();

        effector.provision(d, source()).block();

        Set<String> second = ruleIds();
        List<String> expected = new java.util.ArrayList<>();
        second.forEach(id -> expected.add("upsert " + id));
        first.forEach(id -> expected.add("delete " + id));
        assertThat(mirror.calls).containsExactlyInAnyOrderElementsOf(expected);
        assertThat(mirror.calls.subList(0, 6)).allMatch(c -> c.startsWith("upsert "));
        assertThat(mirror.calls.subList(6, 12)).allMatch(c -> c.startsWith("delete "));
    }

    // ── a rule is never left without its record ──────────────────────────────────────

    @Test
    void recordingFailsPartWay_theRulesAlreadyWrittenAreRolledBack_andNothingFurtherRuns() {
        SubscribedArgoCd argo = new SubscribedArgoCd();
        // Six rules to write; the record of the THIRD fails, after two rule+record pairs and a
        // third rule have been written inside the transaction.
        AddServiceEffector effector = effectorWhoseRecordFails(argo, 3);

        assertThatThrownBy(() -> effector.provision(deployment("dep-owncast", "streaming"), source()).block())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("record store down");

        assertThat(ruleIds()).isEmpty();        // not two, not three: none
        assertThat(records()).isEmpty();
        assertThat(argo.requested).isEmpty();   // the ArgoCD Application was never requested
    }

    @Test
    void recordingFailsOnAReProvision_theEarlierRuleSetAndItsRecordsAreUntouched() {
        SubscribedArgoCd argo = new SubscribedArgoCd();
        ServiceDeployment d = deployment("dep-owncast", "streaming");
        effector(argo, fullProfile()).provision(d, source()).block();
        Set<String> first = ruleIds();
        assertThat(first).hasSize(6);
        assertThat(argo.requested).containsExactly("acme-test-owncast");

        // The LAST record fails: all six new rules are written and five recorded by then.
        AddServiceEffector failing = effectorWhoseRecordFails(argo, 6);
        assertThatThrownBy(() -> failing.provision(d, source()).block())
                .isInstanceOf(IllegalStateException.class);

        assertThat(ruleIds()).isEqualTo(first);
        assertThat(recordedIds(false)).isEqualTo(first);
        assertThat(recordedIds(true)).isEmpty();
        assertThat(argo.requested).hasSize(1);   // the first provision's request only

        // and the deployment can still be torn down completely
        effector(argo, fullProfile()).teardown(d).block();
        assertThat(ruleIds()).isEmpty();
    }

    // ── what a recorded id can and cannot remove ─────────────────────────────────────

    @Test
    void aRecordedIdCanOnlyRemoveARuleOfTheDeploymentsOwnBrand() {
        RouteAccessService ra = EffectorFixture.routeAccess(db);
        // Another brand's rule, recorded (by a bad write or a bug) against THIS brand's
        // deployment. The delete is scoped to the deployment's domain, so it must stay.
        RouteRule foreign = ra.add(new RouteRule(null, "other-test-be-gateway", "/api/owncast/",
                "ROLE_OWNCAST", null, true, "other.test")).block();
        EffectorFixture.ruleRecords(db).record("dep-owncast", foreign.id()).block();
        AddServiceEffector effector = EffectorFixture.effector(db, new AddServiceEffectorTest.RecordingArgoCd(), ra);

        effector.teardown(deployment("dep-owncast", null)).block();

        assertThat(ruleIds()).containsExactly(foreign.id());
    }

    @Test
    void aRecordedRuleAnAdminAlreadyDeleted_doesNotBlockTeardown() {
        RouteAccessService ra = EffectorFixture.routeAccess(db);
        AddServiceEffectorTest.RecordingArgoCd argo = new AddServiceEffectorTest.RecordingArgoCd();
        AddServiceEffector effector = EffectorFixture.effector(db, argo, ra, null, fullProfile());
        ServiceDeployment d = deployment("dep-owncast", "streaming");
        effector.provision(d, source()).block();
        Set<String> written = ruleIds();
        String byHand = written.iterator().next();
        db.sql("DELETE FROM gateway_route_access WHERE id = :id").bind("id", UUID.fromString(byHand))
                .fetch().rowsUpdated().block();

        effector.teardown(d).block();

        assertThat(ruleIds()).isEmpty();
        assertThat(recordedIds(true)).isEqualTo(written);
        assertThat(argo.deleted).containsExactly("acme-test-owncast");
    }

    // ── a deployment without an id ───────────────────────────────────────────────────

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void provision_ofADeploymentWithoutAnId_isRefusedBeforeAnythingIsWritten(String id) {
        AddServiceEffectorTest.RecordingArgoCd argo = new AddServiceEffectorTest.RecordingArgoCd();
        AppProfileRepository profiles = mock(AppProfileRepository.class);
        AddServiceEffector effector = effector(argo, profiles);

        assertThatThrownBy(() -> effector.provision(deployment(id, "streaming"), source()).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("deployment id is required")
                .extracting(e -> ((ApiException) e).status().value()).isEqualTo(400);

        assertThat(ruleIds()).isEmpty();
        assertThat(records()).isEmpty();
        assertThat(argo.created).isEmpty();
        verifyNoInteractions(profiles);
    }

    @Test
    void teardown_ofADeploymentWithoutAnId_hasNoRecord_soItTakesTheByShapePath() {
        RouteAccessService ra = EffectorFixture.routeAccess(db);
        RouteRule old = ra.add(new RouteRule(null, GW, "/api/owncast/", "ROLE_OWNCAST", null, true, BRAND)).block();
        RouteRule denied = ra.add(new RouteRule(null, GW, "/api/owncast/", "ROLE_OWNCAST", "mallory", false, BRAND)).block();
        AddServiceEffector effector = EffectorFixture.effector(db, new AddServiceEffectorTest.RecordingArgoCd(), ra);

        effector.teardown(deployment(null, null)).block();

        assertThat(ruleIds()).containsExactly(denied.id()).doesNotContain(old.id());
    }
}
