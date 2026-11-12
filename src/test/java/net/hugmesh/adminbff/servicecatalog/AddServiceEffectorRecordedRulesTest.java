package net.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * WHICH route-access rules {@link AddServiceEffector#teardown} removes: the ones the same
 * deployment's {@link AddServiceEffector#provision} wrote, and no others. Every case reads the
 * real {@code gateway_route_access} table back and compares row IDS, so "the right rule survived"
 * cannot be satisfied by a different row of the same shape.
 *
 * <p>The cases a teardown that matches on (pattern, role) gets wrong:
 * <ul>
 *   <li>a per-user or deny rule on the deployment's own derived pair (and on a profile pair);</li>
 *   <li>two deployments of one brand that use the SAME profile, or whose grants overlap in any
 *       other way (a profile naming a sibling's derived pair; the same service deployed twice):
 *       tearing one down must leave the other every rule it wrote;</li>
 *   <li>a rule that already existed with exactly the shape of a grant;</li>
 *   <li>a profile deleted or edited between provision and teardown;</li>
 *   <li>a second provision of one deployment, and a second teardown.</li>
 * </ul>
 * The last case pins the one path that still matches by shape: a deployment with NO recorded
 * rules (provisioned before rules were recorded) loses exactly the one rule that provision wrote.
 *
 * <p>The effector is built only through {@link EffectorFixture}; nothing here names its
 * constructor or the table the records live in.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class AddServiceEffectorRecordedRulesTest {

    private static final String BRAND = "acme.test";
    private static final String GW = "acme-test-be-gateway";

    /** 3 patterns x 2 roles once de-duplicated against the derived values, MFA required. */
    private static final String FULL_PROFILE = "{"
            + "\"roles\":[\"ROLE_ADMIN\",\"ROLE_OWNCAST\"],"
            + "\"exposure\":{\"routes\":[\"/api/owncast/\",\"/api/owncast/**\",\"/ws/owncast/**\"],"
            + "\"mfaRequired\":true}}";

    /** The profile two sibling deployments share: one extra route, one extra role. */
    private static final String SHARED_PROFILE =
            "{\"roles\":[\"ROLE_ADMIN\"],\"exposure\":{\"routes\":[\"/ws/**\"]}}";

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        EffectorFixture.clear(db);
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────

    private RouteAccessService routeAccess() {
        return EffectorFixture.routeAccess(db);
    }

    private AddServiceEffector effector(RouteAccessService ra, AppProfileRepository profiles) {
        return EffectorFixture.effector(db, new AddServiceEffectorTest.RecordingArgoCd(), ra, null, profiles);
    }

    private List<RouteRule> allRules() {
        return new RouteAccessRepository(R2dbcRepos.of(db, RouteAccessRowRepository.class))
                .list().collectList().block();
    }

    private Set<String> allIds() {
        Set<String> out = new TreeSet<>();
        allRules().forEach(r -> out.add(r.id()));
        return out;
    }

    /** Every rule as one line, SORTED but not de-duplicated: two identical rows are two lines. */
    private List<String> allShapes() {
        List<String> out = new ArrayList<>();
        for (RouteRule r : allRules()) {
            out.add(r.domain() + "|" + r.gateway() + "|" + r.urlPattern() + "|" + r.role() + "|"
                    + r.casdoorUser() + "|allow=" + r.allow() + "|mfa=" + r.mfaRequired());
        }
        Collections.sort(out);
        return out;
    }

    /** The line {@link #allShapes} prints for a rule a provision writes in {@link #BRAND}. */
    private static String granted(String pattern, String role, boolean mfa) {
        return BRAND + "|" + GW + "|" + pattern + "|" + role + "|null|allow=true|mfa=" + mfa;
    }

    private long count(String pattern, String role) {
        return allRules().stream()
                .filter(r -> pattern.equals(r.urlPattern()) && role.equals(r.role())).count();
    }

    /** Insert a rule by hand, exactly as the route-access admin API would, and return it. */
    private static RouteRule plant(RouteAccessService ra, String gateway, String pattern, String role,
                                   String user, boolean allow, String domain, boolean mfa) {
        return ra.add(new RouteRule(null, gateway, pattern, role, user, allow, domain, mfa)).block();
    }

    private static ServiceDeployment deployment(String id, String service, String profileRef) {
        return new ServiceDeployment(id, BRAND, service, profileRef,
                ServiceDeployment.STATE_ACTIVE, Instant.now(), null, "teardown",
                ServiceDeployment.PROP_PENDING, null, "root");
    }

    private static ServiceSource source(String service) {
        return new ServiceSource(ServiceSource.Kind.GIT, "https://forgejo/acme/" + service, "deploy/", "HEAD");
    }

    private static AppProfile profile(String name, String json) {
        return new AppProfile("p-" + name, name, json, "root", Instant.now(), Instant.now());
    }

    /** An app_profile store that holds exactly one profile, unchanged for the whole test. */
    private static AppProfileRepository profiles(String name, String json) {
        AppProfileRepository profiles = mock(AppProfileRepository.class);
        when(profiles.findByName(name)).thenReturn(Mono.just(profile(name, json)));
        return profiles;
    }

    // ── a per-user or deny rule is never removed ─────────────────────────────────────

    @Test
    void perUserDenyOnTheDerivedPair_survivesProvisionAndTeardown() {
        RouteAccessService ra = routeAccess();
        // Row for row the rule the review planted: a per-user DENY on the service's OWN derived
        // (pattern, role), same brand, same gateway.
        RouteRule mallory = plant(ra, GW, "/api/owncast/", "ROLE_OWNCAST", "mallory", false, BRAND, false);
        AddServiceEffector effector = effector(ra, profiles("streaming", FULL_PROFILE));
        ServiceDeployment d = deployment("dep-owncast", "owncast", "streaming");

        effector.provision(d, source("owncast")).block();
        assertThat(allRules()).hasSize(1 + 6);

        effector.teardown(d).block();

        assertThat(allIds()).containsExactly(mallory.id());
        assertThat(allShapes()).containsExactly(
                BRAND + "|" + GW + "|/api/owncast/|ROLE_OWNCAST|mallory|allow=false|mfa=false");
    }

    @Test
    void everyPerUserOrDenyRuleOnAGrantedPair_survivesProvisionAndTeardown() {
        RouteAccessService ra = routeAccess();
        // On the derived pair AND on a profile-derived pair: a per-user deny, a per-user allow
        // and a role-based deny. None of them is a rule provision writes.
        for (String[] pair : new String[][] {{"/api/owncast/", "ROLE_OWNCAST"}, {"/ws/owncast/**", "ROLE_ADMIN"}}) {
            plant(ra, GW, pair[0], pair[1], "mallory", false, BRAND, false);
            plant(ra, GW, pair[0], pair[1], "alice", true, BRAND, false);
            plant(ra, GW, pair[0], pair[1], null, false, BRAND, false);
        }
        Set<String> planted = allIds();
        assertThat(planted).hasSize(6);
        AddServiceEffector effector = effector(ra, profiles("streaming", FULL_PROFILE));
        ServiceDeployment d = deployment("dep-owncast", "owncast", "streaming");

        effector.provision(d, source("owncast")).block();
        assertThat(allRules()).hasSize(6 + 6);

        effector.teardown(d).block();

        assertThat(allIds()).isEqualTo(planted);
    }

    // ── a sibling deployment's rule is never removed ─────────────────────────────────

    @Test
    void twoDeploymentsSharingOneProfile_tearingOneDown_leavesTheOtherEveryRuleItWrote() {
        RouteAccessService ra = routeAccess();
        AddServiceEffector effector = effector(ra, profiles("shared", SHARED_PROFILE));
        ServiceDeployment owncast = deployment("dep-owncast", "owncast", "shared");
        ServiceDeployment forum = deployment("dep-forum", "forum", "shared");

        effector.provision(owncast, source("owncast")).block();
        effector.provision(forum, source("forum")).block();
        // Each wrote ({derived pattern} ∪ {/ws/**}) x ({derived role} ∪ {ROLE_ADMIN}). The pair
        // (/ws/**, ROLE_ADMIN) is granted by BOTH, as two rows.
        assertThat(allRules()).hasSize(8);
        assertThat(count("/ws/**", "ROLE_ADMIN")).isEqualTo(2);

        effector.teardown(owncast).block();

        assertThat(allShapes()).containsExactlyInAnyOrder(
                granted("/api/forum/", "ROLE_FORUM", false),
                granted("/api/forum/", "ROLE_ADMIN", false),
                granted("/ws/**", "ROLE_FORUM", false),
                granted("/ws/**", "ROLE_ADMIN", false));

        effector.teardown(forum).block();
        assertThat(allRules()).isEmpty();
    }

    @Test
    void aProfileNamingASiblingsDerivedPair_tearingItDown_leavesTheSiblingsDerivedRule() {
        RouteAccessService ra = routeAccess();
        AddServiceEffector effector = effector(ra, profiles("wide",
                "{\"roles\":[\"ROLE_FORUM\"],\"exposure\":{\"routes\":[\"/api/forum/\"]}}"));
        ServiceDeployment forum = deployment("dep-forum", "forum", null);
        ServiceDeployment tube = deployment("dep-tube", "tube", "wide");

        effector.provision(forum, source("forum")).block();
        Set<String> forumRules = allIds();
        assertThat(forumRules).hasSize(1);
        // tube's profile grants ROLE_FORUM on /api/forum/: the same (pattern, role) as forum's
        // own derived rule, written as a second row.
        effector.provision(tube, source("tube")).block();
        assertThat(allRules()).hasSize(1 + 4);
        assertThat(count("/api/forum/", "ROLE_FORUM")).isEqualTo(2);

        effector.teardown(tube).block();

        assertThat(allIds()).isEqualTo(forumRules);
        assertThat(allShapes()).containsExactly(granted("/api/forum/", "ROLE_FORUM", false));
    }

    @Test
    void tearingDownADeployment_leavesTheSiblingWhoseProfileNamesItsDerivedPair() {
        RouteAccessService ra = routeAccess();
        AddServiceEffector effector = effector(ra, profiles("wide",
                "{\"roles\":[\"ROLE_FORUM\"],\"exposure\":{\"routes\":[\"/api/forum/\"]}}"));
        ServiceDeployment forum = deployment("dep-forum", "forum", null);
        ServiceDeployment tube = deployment("dep-tube", "tube", "wide");

        effector.provision(forum, source("forum")).block();
        Set<String> forumRules = allIds();
        effector.provision(tube, source("tube")).block();
        Set<String> tubeRules = allIds();
        tubeRules.removeAll(forumRules);
        assertThat(tubeRules).hasSize(4);

        effector.teardown(forum).block();   // the other way round: the DERIVED owner goes first

        assertThat(allIds()).isEqualTo(tubeRules);
        assertThat(count("/api/forum/", "ROLE_FORUM")).isEqualTo(1);
    }

    @Test
    void theSameServiceDeployedTwice_tearingOneDown_leavesTheOthersDerivedRule() {
        RouteAccessService ra = routeAccess();
        AddServiceEffector effector = effector(ra, null);
        ServiceDeployment first = deployment("dep-a", "owncast", null);
        ServiceDeployment second = deployment("dep-b", "owncast", null);

        effector.provision(first, source("owncast")).block();
        Set<String> firstRules = allIds();
        effector.provision(second, source("owncast")).block();
        Set<String> secondRules = allIds();
        secondRules.removeAll(firstRules);
        assertThat(firstRules).hasSize(1);
        assertThat(secondRules).hasSize(1);

        effector.teardown(first).block();
        assertThat(allIds()).isEqualTo(secondRules);

        effector.teardown(second).block();
        assertThat(allRules()).isEmpty();
    }

    // ── a rule that was already there is never removed ───────────────────────────────

    @Test
    void aRuleThatAlreadyExistedWithTheShapeOfAGrant_isNotRemoved() {
        RouteAccessService ra = routeAccess();
        // Identical, field for field, to two of the six rules the provision below writes: one
        // on a profile pair and one on the derived pair (the profile requires MFA).
        plant(ra, GW, "/ws/owncast/**", "ROLE_ADMIN", null, true, BRAND, true);
        plant(ra, GW, "/api/owncast/", "ROLE_OWNCAST", null, true, BRAND, true);
        Set<String> planted = allIds();
        AddServiceEffector effector = effector(ra, profiles("streaming", FULL_PROFILE));
        ServiceDeployment d = deployment("dep-owncast", "owncast", "streaming");

        effector.provision(d, source("owncast")).block();
        assertThat(allRules()).hasSize(2 + 6);
        assertThat(count("/ws/owncast/**", "ROLE_ADMIN")).isEqualTo(2);
        assertThat(count("/api/owncast/", "ROLE_OWNCAST")).isEqualTo(2);

        effector.teardown(d).block();

        assertThat(allIds()).isEqualTo(planted);
    }

    @Test
    void aRuleThatAlreadyExistedWithTheShapeOfTheDerivedRule_isNotRemoved_withoutAProfile() {
        RouteAccessService ra = routeAccess();
        // No profile: the provision writes exactly one rule, and this is its twin.
        RouteRule twin = plant(ra, GW, "/api/owncast/", "ROLE_OWNCAST", null, true, BRAND, false);
        AddServiceEffector effector = effector(ra, null);
        ServiceDeployment d = deployment("dep-owncast", "owncast", null);

        effector.provision(d, source("owncast")).block();
        assertThat(allRules()).hasSize(2);

        effector.teardown(d).block();

        assertThat(allIds()).containsExactly(twin.id());
    }

    // ── the profile is not read again ────────────────────────────────────────────────

    @Test
    void profileDeletedBeforeTeardown_everyRuleProvisionWroteIsStillRemoved() {
        RouteAccessService ra = routeAccess();
        AppProfileRepository profiles = mock(AppProfileRepository.class);
        when(profiles.findByName("streaming"))
                .thenReturn(Mono.just(profile("streaming", FULL_PROFILE)))
                .thenReturn(Mono.empty());   // deleted: any later lookup finds nothing
        AddServiceEffector effector = effector(ra, profiles);
        ServiceDeployment d = deployment("dep-owncast", "owncast", "streaming");

        effector.provision(d, source("owncast")).block();
        assertThat(allRules()).hasSize(6);

        effector.teardown(d).block();

        assertThat(allRules()).isEmpty();
        verify(profiles, times(1)).findByName("streaming");   // provision only
    }

    @Test
    void profileEditedBeforeTeardown_removesWhatProvisionWrote_notWhatTheProfileNamesNow() {
        RouteAccessService ra = routeAccess();
        // The grant the EDITED profile names. It was there before and is nobody's.
        RouteRule bystander = plant(ra, GW, "/api/forum/", "ROLE_FORUM", null, true, BRAND, false);
        AppProfileRepository profiles = mock(AppProfileRepository.class);
        when(profiles.findByName("streaming"))
                .thenReturn(Mono.just(profile("streaming",
                        "{\"roles\":[\"ROLE_ADMIN\"],\"exposure\":{\"routes\":[\"/ws/owncast/**\"]}}")))
                .thenReturn(Mono.just(profile("streaming",
                        "{\"roles\":[\"ROLE_FORUM\"],\"exposure\":{\"routes\":[\"/api/forum/\"]}}")));
        AddServiceEffector effector = effector(ra, profiles);
        ServiceDeployment d = deployment("dep-owncast", "owncast", "streaming");

        effector.provision(d, source("owncast")).block();
        assertThat(allRules()).hasSize(1 + 4);

        effector.teardown(d).block();

        assertThat(allIds()).containsExactly(bystander.id());
    }

    // ── a second provision, a second teardown ────────────────────────────────────────

    @Test
    void provisioningAgain_replacesTheDeploymentsRules_andTeardownLeavesNothingOfThem() {
        RouteAccessService ra = routeAccess();
        RouteRule bystander = plant(ra, GW, "/api/owncast/", "ROLE_OWNCAST", "mallory", false, BRAND, false);
        AppProfileRepository profiles = mock(AppProfileRepository.class);
        when(profiles.findByName("streaming"))
                .thenReturn(Mono.just(profile("streaming", FULL_PROFILE)))
                .thenReturn(Mono.just(profile("streaming", FULL_PROFILE)))
                // then edited: one route fewer, MFA no longer required
                .thenReturn(Mono.just(profile("streaming",
                        "{\"roles\":[\"ROLE_ADMIN\"],\"exposure\":{\"routes\":[\"/api/owncast/**\"]}}")));
        AddServiceEffector effector = effector(ra, profiles);
        ServiceDeployment d = deployment("dep-owncast", "owncast", "streaming");
        String bystanderShape = BRAND + "|" + GW + "|/api/owncast/|ROLE_OWNCAST|mallory|allow=false|mfa=false";

        effector.provision(d, source("owncast")).block();
        List<String> afterFirst = allShapes();
        assertThat(afterFirst).hasSize(1 + 6);

        effector.provision(d, source("owncast")).block();   // a retry: the same profile
        assertThat(allShapes()).isEqualTo(afterFirst);       // no second copy of any rule

        effector.provision(d, source("owncast")).block();   // after the edit
        assertThat(allShapes()).containsExactlyInAnyOrder(
                bystanderShape,
                granted("/api/owncast/", "ROLE_OWNCAST", false),
                granted("/api/owncast/", "ROLE_ADMIN", false),
                granted("/api/owncast/**", "ROLE_OWNCAST", false),
                granted("/api/owncast/**", "ROLE_ADMIN", false));

        effector.teardown(d).block();
        assertThat(allIds()).containsExactly(bystander.id());
    }

    @Test
    void aSecondTeardown_removesNothingMore() {
        RouteAccessService ra = routeAccess();
        AddServiceEffector effector = effector(ra, null);
        ServiceDeployment d = deployment("dep-owncast", "owncast", null);
        effector.provision(d, source("owncast")).block();
        effector.teardown(d).block();
        assertThat(allRules()).isEmpty();
        // Hand-made afterwards, with exactly the shape of the rule the deployment once had.
        RouteRule later = plant(ra, GW, "/api/owncast/", "ROLE_OWNCAST", null, true, BRAND, false);

        effector.teardown(d).block();

        assertThat(allIds()).containsExactly(later.id());
    }

    // ── no recorded rules: the one path that still matches by shape ──────────────────

    @Test
    void aDeploymentWithNoRecordedRules_losesExactlyTheRuleItsOldProvisionWrote() {
        RouteAccessService ra = routeAccess();
        // What a provision wrote BEFORE rules were recorded: the one derived rule, role-based,
        // allow, no MFA requirement, on the brand's be-gateway. Nothing records it.
        RouteRule old = plant(ra, GW, "/api/owncast/", "ROLE_OWNCAST", null, true, BRAND, false);
        // Same brand, same (pattern, role), and every one of them must stay:
        plant(ra, GW, "/api/owncast/", "ROLE_OWNCAST", "mallory", false, BRAND, false);      // per-user deny
        plant(ra, GW, "/api/owncast/", "ROLE_OWNCAST", "alice", true, BRAND, false);         // per-user allow
        plant(ra, GW, "/api/owncast/", "ROLE_OWNCAST", null, false, BRAND, false);           // role-based deny
        plant(ra, "acme-test-fe-gateway", "/api/owncast/", "ROLE_OWNCAST", null, true, BRAND, false);
        plant(ra, GW, "/api/owncast/", "ROLE_OWNCAST", null, true, BRAND, true);             // MFA required
        // Another brand's rule of the very same shape, and a different pattern in this brand.
        plant(ra, GW, "/api/owncast/", "ROLE_OWNCAST", null, true, "other.test", false);
        plant(ra, GW, "/api/owncast/**", "ROLE_OWNCAST", null, true, BRAND, false);
        // A second deployment of the same service, provisioned now: its rule has the old rule's
        // exact shape, and it is recorded.
        AddServiceEffector effector = effector(ra, null);
        effector.provision(deployment("dep-sibling", "owncast", null), source("owncast")).block();
        Set<String> expected = allIds();
        assertThat(expected).hasSize(9);
        expected.remove(old.id());

        effector.teardown(deployment("dep-old", "owncast", null)).block();

        assertThat(allIds()).isEqualTo(expected);
    }
}
