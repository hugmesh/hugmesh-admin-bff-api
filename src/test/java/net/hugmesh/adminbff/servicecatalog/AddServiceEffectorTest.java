package net.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.argocd.ArgoCdClient;
import net.hugmesh.adminbff.argocd.NoopArgoCdClient;
import net.hugmesh.adminbff.routeaccess.RouteAccessRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.adminbff.routeaccess.RouteMirror;
import net.hugmesh.adminbff.routeaccess.RouteRule;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.commons.web.ApiException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The App-Store {@code AddService} effector — over a real H2 route-access store so the
 * route-rule add/remove leg is exercised end to end. Proves:
 * <ul>
 *   <li>SELECT/GIT sources provision: the per-service ArgoCD Application is created, a
 *       per-service route-access rule (role → url pattern, brand-scoped) is added, and the
 *       Casdoor role leg is driven (here: skipped — null client, as in a Casdoor-less run);</li>
 *   <li>DOCKERFILE/ZIP sources are GUARDED with a 400 ("requires the in-cluster builder")
 *       and make NO ArgoCD / route-access effect;</li>
 *   <li>TEARDOWN deletes the Application and removes the matching route rule;</li>
 *   <li>SHIPS DARK: the default {@link NoopArgoCdClient} reports {@code effectorEnabled=false}
 *       and records the would-be calls without a real ArgoCD mutation.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class AddServiceEffectorTest {

    @Autowired DatabaseClient db;

    /** A recording ArgoCD client (no real server) that tracks the create/delete calls. */
    static final class RecordingArgoCd implements ArgoCdClient {
        final List<String> created = new ArrayList<>();
        final List<String> deleted = new ArrayList<>();
        @Override public Mono<String> createApplication(String name, String repoUrl, String path,
                                                        String targetRevision, String destNamespace) {
            created.add(name + "|" + repoUrl + "|" + destNamespace);
            return Mono.just(name);
        }
        @Override public Mono<Boolean> deleteApplication(String name) {
            deleted.add(name);
            return Mono.just(true);
        }
        @Override public boolean isReal() { return false; }
    }

    static final class NoopMirror implements RouteMirror {
        @Override public Mono<Void> upsert(RouteRule rule) { return Mono.empty(); }
        @Override public Mono<Void> delete(String id) { return Mono.empty(); }
    }

    private RouteAccessService routeAccess() {
        return new RouteAccessService(new RouteAccessRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.routeaccess.RouteAccessRowRepository.class)), new NoopMirror());
    }

    private ServiceDeployment deployment(String domain, String service) {
        return new ServiceDeployment("dep-1", domain, service, null,
                ServiceDeployment.STATE_ACTIVE, Instant.now(), null, "teardown",
                ServiceDeployment.PROP_PENDING, null, "root");
    }

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM gateway_route_access").fetch().rowsUpdated().block();
    }

    @Test
    void provision_gitSource_createsApplication_andAddsBrandScopedRouteRule() {
        RecordingArgoCd argo = new RecordingArgoCd();
        RouteAccessService ra = routeAccess();
        AddServiceEffector effector = new AddServiceEffector(argo, /*casdoor*/ null, ra, /*builder*/ null);

        assertThat(effector.effectorEnabled()).isFalse();   // ships dark (noop-equivalent)

        String app = effector.provision(deployment("acme.test", "owncast"),
                new ServiceSource(ServiceSource.Kind.GIT, "https://forgejo/acme/owncast",
                        "deploy/", "HEAD")).block();

        assertThat(app).isEqualTo("acme-test-owncast");
        assertThat(argo.created).hasSize(1);
        assertThat(argo.created.get(0)).contains("acme-test-owncast", "acme-test-be");

        // a per-service route rule was added, scoped to the brand, role=ROLE_OWNCAST.
        List<RouteRule> rules = new RouteAccessRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.routeaccess.RouteAccessRowRepository.class)).list().collectList().block();
        assertThat(rules).anySatisfy(r -> {
            assertThat(r.role()).isEqualTo("ROLE_OWNCAST");
            assertThat(r.urlPattern()).isEqualTo("/api/owncast/");
            assertThat(r.domain()).isEqualTo("acme.test");
            assertThat(r.allow()).isTrue();
        });
    }

    @Test
    void provision_dockerfileSource_isGuarded_noEffect() {
        RecordingArgoCd argo = new RecordingArgoCd();
        AddServiceEffector effector = new AddServiceEffector(argo, null, routeAccess(), /*builder*/ null);

        assertThatThrownBy(() -> effector.provision(deployment("acme.test", "owncast"),
                new ServiceSource(ServiceSource.Kind.DOCKERFILE, "https://forgejo/acme/owncast",
                        "deploy/", "HEAD")).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("in-cluster image builder");

        assertThat(argo.created).isEmpty();
        assertThat(new RouteAccessRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.routeaccess.RouteAccessRowRepository.class)).list().collectList().block()).isEmpty();
    }

    @Test
    void provision_zipSource_isGuarded() {
        AddServiceEffector effector = new AddServiceEffector(new RecordingArgoCd(), null, routeAccess(), /*builder*/ null);
        assertThatThrownBy(() -> effector.provision(deployment("acme.test", "x"),
                new ServiceSource(ServiceSource.Kind.ZIP, "r", null, null)).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("requires the in-cluster image builder");
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "http://169.254.169.254/latest/meta-data/",   // cloud-metadata SSRF (plaintext http)
            "file:///etc/passwd",                          // local file read
            "git://",                                      // host-less git native
    })
    void provision_hostileRepoUrl_isRejected_beforeAnyArgoCdCall(String hostileRepoUrl) {
        RecordingArgoCd argo = new RecordingArgoCd();
        RouteAccessService ra = routeAccess();
        AddServiceEffector effector = new AddServiceEffector(argo, /*casdoor*/ null, ra, /*builder*/ null);

        // LIVE (SELECT/GIT) path: the symmetric structural SSRF re-check fails CLOSED with the
        // same 400 the build path throws — BEFORE argoCd.createApplication() is ever invoked.
        assertThatThrownBy(() -> effector.provision(deployment("acme.test", "owncast"),
                new ServiceSource(ServiceSource.Kind.GIT, hostileRepoUrl, "deploy/", "HEAD")).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("invalid source repoUrl");

        // No ArgoCD Application was created and no route-access rule was written.
        assertThat(argo.created).isEmpty();
        assertThat(new RouteAccessRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.routeaccess.RouteAccessRowRepository.class)).list().collectList().block()).isEmpty();
    }

    @Test
    void provision_validHttpsRepoUrl_stillProvisions() {
        RecordingArgoCd argo = new RecordingArgoCd();
        AddServiceEffector effector = new AddServiceEffector(argo, /*casdoor*/ null, routeAccess(), /*builder*/ null);

        // A valid https repo passes the structural SSRF re-check and provisions normally.
        String app = effector.provision(deployment("acme.test", "owncast"),
                new ServiceSource(ServiceSource.Kind.GIT, "https://forgejo.acme.test/acme/owncast",
                        "deploy/", "HEAD")).block();

        assertThat(app).isEqualTo("acme-test-owncast");
        assertThat(argo.created).hasSize(1);
        assertThat(argo.created.get(0)).contains("https://forgejo.acme.test/acme/owncast");
    }

    @Test
    void provision_missingRepoUrl_isBadRequest() {
        AddServiceEffector effector = new AddServiceEffector(new RecordingArgoCd(), null, routeAccess(), /*builder*/ null);
        assertThatThrownBy(() -> effector.provision(deployment("acme.test", "owncast"),
                new ServiceSource(ServiceSource.Kind.SELECT, null, null, null)).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("repoUrl is required");
    }

    @Test
    void teardown_deletesApplication_andRemovesMatchingRouteRule() {
        RecordingArgoCd argo = new RecordingArgoCd();
        RouteAccessService ra = routeAccess();
        AddServiceEffector effector = new AddServiceEffector(argo, null, ra, /*builder*/ null);

        // provision then tear down the SAME deployment.
        ServiceDeployment d = deployment("acme.test", "owncast");
        effector.provision(d, new ServiceSource(ServiceSource.Kind.GIT,
                "https://forgejo/acme/owncast", "deploy/", "HEAD")).block();
        assertThat(new RouteAccessRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.routeaccess.RouteAccessRowRepository.class)).list().collectList().block()).hasSize(1);

        effector.teardown(d).block();

        assertThat(argo.deleted).containsExactly("acme-test-owncast");
        // the per-service route rule is gone (matched by role + url pattern + brand).
        assertThat(new RouteAccessRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.routeaccess.RouteAccessRowRepository.class)).list().collectList().block()).isEmpty();
    }

    /**
     * Stub {@link KanikoBuildLauncher} that records calls and returns a fake image reference.
     * Avoids touching the Fabric8 {@code KubernetesClient} — pure Mono chain testing.
     */
    static final class RecordingBuilder extends KanikoBuildLauncher {
        final java.util.List<String> buildCalls = new java.util.ArrayList<>();

        RecordingBuilder() {
            // Null k8s client — never called; the build() override short-circuits. Empty
            // repo-host-allowlist (4th arg) = any valid host, matching the default behaviour.
            super(null, "test-builds", "registry.test", "");
        }

        @Override
        public reactor.core.publisher.Mono<String> build(String brand, String serviceKey,
                                                          ServiceSource source) {
            buildCalls.add(brand + "/" + serviceKey + ":" + source.kind());
            return reactor.core.publisher.Mono.just("registry.test/" + brand + "/" + serviceKey + ":sha123");
        }
    }

    @Test
    void provision_dockerfileSource_withBuilder_callsBuildThenCreateApplication() {
        RecordingArgoCd argo = new RecordingArgoCd();
        RecordingBuilder builder = new RecordingBuilder();
        AddServiceEffector effector = new AddServiceEffector(argo, /*casdoor*/ null, routeAccess(), builder);

        String app = effector.provision(deployment("acme.test", "tube"),
                new ServiceSource(ServiceSource.Kind.DOCKERFILE, "https://forgejo/acme/tube",
                        null, "main")).block();

        // builder.build() must have been called BEFORE argoCd.createApplication().
        assertThat(builder.buildCalls).hasSize(1);
        assertThat(builder.buildCalls.get(0)).contains("tube").contains("DOCKERFILE");

        // ArgoCD Application was still created.
        assertThat(argo.created).hasSize(1);
        assertThat(argo.created.get(0)).contains("acme-test-tube");
        assertThat(app).isEqualTo("acme-test-tube");
    }

    // ── App-profile resolution (catalog-ui#3, first slice) ───────────────────────────
    //
    // The app_profile store is a Mockito mock; the route-access store stays the real H2 one so
    // the rule set each case writes (and teardown removes) is read back from the table.

    private static final String GW = "acme-test-be-gateway";

    private List<RouteRule> allRules() {
        return new RouteAccessRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db,
                net.hugmesh.adminbff.routeaccess.RouteAccessRowRepository.class)).list().collectList().block();
    }

    /** Every rule reduced to the fields provision writes, for whole-set comparisons. */
    private static java.util.Set<String> shape(List<RouteRule> rules) {
        java.util.Set<String> out = new java.util.TreeSet<>();
        for (RouteRule r : rules) {
            out.add(r.domain() + "|" + r.gateway() + "|" + r.urlPattern() + "|" + r.role() + "|"
                    + r.casdoorUser() + "|allow=" + r.allow() + "|mfa=" + r.mfaRequired());
        }
        return out;
    }

    private static ServiceDeployment deploymentWithProfile(String profileRef) {
        return new ServiceDeployment("dep-p", "acme.test", "owncast", profileRef,
                ServiceDeployment.STATE_ACTIVE, Instant.now(), null, "teardown",
                ServiceDeployment.PROP_PENDING, null, "root");
    }

    private static ServiceSource gitSource() {
        return new ServiceSource(ServiceSource.Kind.GIT, "https://forgejo/acme/owncast", "deploy/", "HEAD");
    }

    private static AppProfile profile(String name, String json) {
        return new AppProfile("p-1", name, json, "root", Instant.now(), Instant.now());
    }

    /** Routes, roles and mfaRequired, each also repeating the DERIVED value once (the
     *  de-duplication case), plus resources/certs/ports that must stay recorded-only. */
    private static final String FULL_PROFILE = "{"
            + "\"resources\":{\"cpu\":\"500m\",\"memory\":\"512Mi\"},"
            + "\"roles\":[\"ROLE_ADMIN\",\"ROLE_OWNCAST\"],"
            + "\"certs\":{\"altNames\":[\"owncast.acme-be.svc.cluster.local\"],\"ttl\":\"720h\"},"
            + "\"exposure\":{\"routes\":[\"/api/owncast/\",\"/api/owncast/**\",\"/ws/owncast/**\"],"
            + "\"ports\":[8080],\"mfaRequired\":true}}";

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.NullSource
    @org.junit.jupiter.params.provider.ValueSource(strings = {"", "   "})
    void noProfileRef_isByteIdenticalToTheDerivedRule_andNeverTouchesTheProfileStore(String ref) {
        RecordingArgoCd argo = new RecordingArgoCd();
        AppProfileRepository profiles = org.mockito.Mockito.mock(AppProfileRepository.class);
        AddServiceEffector effector = new AddServiceEffector(argo, null, routeAccess(), null, profiles);

        ServiceDeployment d = deploymentWithProfile(ref);
        String app = effector.provision(d, gitSource()).block();

        assertThat(app).isEqualTo("acme-test-owncast");
        assertThat(argo.created).containsExactly("acme-test-owncast|https://forgejo/acme/owncast|acme-test-be");
        // exactly the one rule provision wrote before profiles were resolved: mfa_required=false.
        assertThat(shape(allRules())).containsExactly(
                "acme.test|" + GW + "|/api/owncast/|ROLE_OWNCAST|null|allow=true|mfa=false");

        effector.teardown(d).block();
        assertThat(allRules()).isEmpty();
        assertThat(argo.deleted).containsExactly("acme-test-owncast");
        org.mockito.Mockito.verifyNoInteractions(profiles);
    }

    @Test
    void profile_routesTimesRoles_allMfaRequired_resourcesAndCertsUnconsumed() {
        RecordingArgoCd argo = new RecordingArgoCd();
        AppProfileRepository profiles = org.mockito.Mockito.mock(AppProfileRepository.class);
        org.mockito.Mockito.when(profiles.findByName("streaming"))
                .thenReturn(Mono.just(profile("streaming", FULL_PROFILE)));
        AddServiceEffector effector = new AddServiceEffector(argo, null, routeAccess(), null, profiles);

        String app = effector.provision(deploymentWithProfile("streaming"), gitSource()).block();

        assertThat(app).isEqualTo("acme-test-owncast");
        // ({derived} ∪ routes) × ({derived role} ∪ roles), de-duplicated: 3 patterns × 2 roles,
        // every one mfa_required, brand-scoped, on the per-domain be-gateway.
        java.util.Set<String> expected = new java.util.TreeSet<>();
        for (String pattern : List.of("/api/owncast/", "/api/owncast/**", "/ws/owncast/**")) {
            for (String role : List.of("ROLE_OWNCAST", "ROLE_ADMIN")) {
                expected.add("acme.test|" + GW + "|" + pattern + "|" + role + "|null|allow=true|mfa=true");
            }
        }
        List<RouteRule> rules = allRules();
        assertThat(rules).hasSize(6);
        assertThat(shape(rules)).isEqualTo(expected);
        // resources/certs/ports are recorded only: the ArgoCD call is byte-identical.
        assertThat(argo.created).containsExactly("acme-test-owncast|https://forgejo/acme/owncast|acme-test-be");
    }

    @Test
    void profile_mfaRequiredAbsent_defaultsFalse_onEveryRule() {
        AppProfileRepository profiles = org.mockito.Mockito.mock(AppProfileRepository.class);
        org.mockito.Mockito.when(profiles.findByName("plain")).thenReturn(Mono.just(profile("plain",
                "{\"roles\":[\"ROLE_MESH\"],\"exposure\":{\"routes\":[\"/ws/owncast/**\"]}}")));
        AddServiceEffector effector = new AddServiceEffector(new RecordingArgoCd(), null, routeAccess(), null, profiles);

        effector.provision(deploymentWithProfile("plain"), gitSource()).block();

        assertThat(allRules()).hasSize(4).allSatisfy(r -> assertThat(r.mfaRequired()).isFalse());
    }

    @Test
    void teardown_removesExactlyWhatProvisionAdded_andLeavesEverythingElse() {
        RouteAccessService ra = routeAccess();
        // Pre-existing rules that teardown must NOT touch: another brand's identical grant, a
        // same-brand rule on an unrelated pattern, and a hand-made per-user rule on a
        // profile-derived (pattern, role) pair.
        ra.add(new RouteRule(null, "other-test-be-gateway", "/api/owncast/**", "ROLE_ADMIN", null, true,
                "other.test", true)).block();
        ra.add(new RouteRule(null, GW, "/api/forum/", "ROLE_ADMIN", null, true, "acme.test")).block();
        ra.add(new RouteRule(null, GW, "/ws/owncast/**", "ROLE_ADMIN", "mallory", false, "acme.test")).block();
        java.util.Set<String> before = shape(allRules());

        RecordingArgoCd argo = new RecordingArgoCd();
        AppProfileRepository profiles = org.mockito.Mockito.mock(AppProfileRepository.class);
        org.mockito.Mockito.when(profiles.findByName("streaming"))
                .thenReturn(Mono.just(profile("streaming", FULL_PROFILE)));
        AddServiceEffector effector = new AddServiceEffector(argo, null, ra, null, profiles);
        ServiceDeployment d = deploymentWithProfile("streaming");

        effector.provision(d, gitSource()).block();
        assertThat(allRules()).hasSize(before.size() + 6);

        effector.teardown(d).block();

        assertThat(shape(allRules())).isEqualTo(before);
        assertThat(argo.deleted).containsExactly("acme-test-owncast");
    }

    @Test
    void teardown_profileDeletedSinceProvision_stillRemovesTheDerivedRuleAndApplication() {
        RecordingArgoCd argo = new RecordingArgoCd();
        AppProfileRepository profiles = org.mockito.Mockito.mock(AppProfileRepository.class);
        org.mockito.Mockito.when(profiles.findByName("streaming"))
                .thenReturn(Mono.just(profile("streaming", FULL_PROFILE)))
                .thenReturn(Mono.empty());
        AddServiceEffector effector = new AddServiceEffector(argo, null, routeAccess(), null, profiles);
        ServiceDeployment d = deploymentWithProfile("streaming");
        effector.provision(d, gitSource()).block();

        effector.teardown(d).block();   // does not fail: an expired lease must still come down

        assertThat(argo.deleted).containsExactly("acme-test-owncast");
        assertThat(allRules()).noneSatisfy(r -> assertThat(r.urlPattern() + r.role())
                .isEqualTo("/api/owncast/ROLE_OWNCAST"));
        // the documented limit: profile-derived rules stay behind (WARN-logged).
        assertThat(allRules()).hasSize(5);
    }

    @Test
    void unknownProfileRef_failsClosedWith422_beforeAnyEffect() {
        RecordingArgoCd argo = new RecordingArgoCd();
        AppProfileRepository profiles = org.mockito.Mockito.mock(AppProfileRepository.class);
        org.mockito.Mockito.when(profiles.findByName("nope")).thenReturn(Mono.empty());
        AddServiceEffector effector = new AddServiceEffector(argo, null, routeAccess(), null, profiles);

        assertThatThrownBy(() -> effector.provision(deploymentWithProfile("nope"), gitSource()).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("app_profile 'nope'")
                .hasMessageContaining("does not exist")
                .extracting(e -> ((ApiException) e).status().value()).isEqualTo(422);

        assertThat(argo.created).isEmpty();
        assertThat(allRules()).isEmpty();
    }

    @Test
    void storedProfileTheSchemaRefuses_failsClosedWith422_beforeAnyEffect() {
        // the legacy flat {"cpu","memory"} body: readable, but resolving it would silently drop
        // every grant / MFA requirement the operator meant, so provision refuses it.
        RecordingArgoCd argo = new RecordingArgoCd();
        AppProfileRepository profiles = org.mockito.Mockito.mock(AppProfileRepository.class);
        org.mockito.Mockito.when(profiles.findByName("legacy"))
                .thenReturn(Mono.just(profile("legacy", "{\"cpu\":\"500m\",\"memory\":\"512Mi\"}")));
        AddServiceEffector effector = new AddServiceEffector(argo, null, routeAccess(), null, profiles);

        assertThatThrownBy(() -> effector.provision(deploymentWithProfile("legacy"), gitSource()).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("app_profile 'legacy' does not match the app-profile schema")
                .extracting(e -> ((ApiException) e).status().value()).isEqualTo(422);

        assertThat(argo.created).isEmpty();
        assertThat(allRules()).isEmpty();
    }

    @Test
    void profileRef_withNoProfileStoreWired_failsClosedWith422() {
        RecordingArgoCd argo = new RecordingArgoCd();
        AddServiceEffector effector = new AddServiceEffector(argo, null, routeAccess(), /*builder*/ null);

        assertThatThrownBy(() -> effector.provision(deploymentWithProfile("streaming"), gitSource()).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("no app_profile store is wired")
                .extracting(e -> ((ApiException) e).status().value()).isEqualTo(422);

        assertThat(argo.created).isEmpty();
        assertThat(allRules()).isEmpty();
    }
}
