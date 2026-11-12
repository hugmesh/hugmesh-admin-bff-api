package net.hugmesh.adminbff.servicecatalog;

import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.transaction.reactive.TransactionalOperator;
import net.hugmesh.adminbff.argocd.ArgoCdClient;
import net.hugmesh.adminbff.routeaccess.RouteAccessRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessRowRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.adminbff.testutil.R2dbcRepos;

/**
 * The ONE place the servicecatalog tests wire an {@link AddServiceEffector} over the slice's
 * real Postgres: the route-access store, the rule-record store and a real R2DBC transaction all
 * run on the {@code ConnectionFactory} behind the autowired {@link DatabaseClient}, so a rule and
 * its record are genuinely written in one transaction.
 *
 * <p>Keeping the construction here means a test body never names the effector's constructor.
 * {@code AddServiceEffectorRecordedRulesTest} relies on that: its bodies are behaviour only, so
 * the same file can be run against a tree whose effector is wired differently.
 */
final class EffectorFixture {

    private EffectorFixture() {
    }

    /** No Casdoor client, no host allowlist; {@code builder} and {@code profiles} may be null. */
    static AddServiceEffector effector(DatabaseClient db, ArgoCdClient argo, RouteAccessService routeAccess,
                                       KanikoBuildLauncher builder, AppProfileRepository profiles) {
        return new AddServiceEffector(argo, null, routeAccess, builder, profiles, ruleRecords(db), tx(db));
    }

    /** No Casdoor client, no host allowlist, no builder, no app_profile store. */
    static AddServiceEffector effector(DatabaseClient db, ArgoCdClient argo, RouteAccessService routeAccess) {
        return effector(db, argo, routeAccess, null, null);
    }

    static RouteAccessService routeAccess(DatabaseClient db) {
        return new RouteAccessService(
                new RouteAccessRepository(R2dbcRepos.of(db, RouteAccessRowRepository.class)),
                new AddServiceEffectorTest.NoopMirror());
    }

    static DeploymentRouteRuleRepository ruleRecords(DatabaseClient db) {
        return new DeploymentRouteRuleRepository(R2dbcRepos.of(db, DeploymentRouteRuleR2dbcRepository.class));
    }

    static TransactionalOperator tx(DatabaseClient db) {
        return TransactionalOperator.create(new R2dbcTransactionManager(db.getConnectionFactory()));
    }

    /** Empty the two tables the effector's route-access leg writes. */
    static void clear(DatabaseClient db) {
        db.sql("DELETE FROM service_deployment_route_rule").fetch().rowsUpdated().block();
        db.sql("DELETE FROM gateway_route_access").fetch().rowsUpdated().block();
    }
}
