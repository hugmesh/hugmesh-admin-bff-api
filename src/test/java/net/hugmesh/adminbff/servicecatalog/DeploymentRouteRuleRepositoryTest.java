package net.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@code service_deployment_route_rule} (changeset 400) through {@link DeploymentRouteRuleRepository},
 * on the slice's real Postgres with the production changelog applied.
 *
 * <p>Besides the store's own semantics this pins the GRANT. Every other test connects as the
 * database owner and so cannot see a missing privilege; the app connects as {@code adminbff_app}.
 * The grant is therefore checked twice: by asking Postgres which verbs the role holds, and by
 * running every statement the store issues AS that role.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DeploymentRouteRuleRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        EffectorFixture.clear(db);
    }

    private DeploymentRouteRuleRepository records() {
        return EffectorFixture.ruleRecords(db);
    }

    private static String newId() {
        return UUID.randomUUID().toString();
    }

    private long rowCount() {
        Long c = db.sql("SELECT count(*) AS c FROM service_deployment_route_rule")
                .map((row, meta) -> row.get("c", Long.class)).one().block();
        return c == null ? 0 : c;
    }

    @Test
    void record_thenLiveRuleIds_areTheDeploymentsOwn() {
        DeploymentRouteRuleRepository records = records();
        String a1 = newId();
        String a2 = newId();
        String b1 = newId();
        records.record("dep-a", a1).block();
        records.record("dep-b", b1).block();
        records.record("dep-a", a2).block();

        assertThat(records.liveRuleIds("dep-a").collectList().block()).containsExactlyInAnyOrder(a1, a2);
        assertThat(records.liveRuleIds("dep-b").collectList().block()).containsExactly(b1);
        assertThat(records.liveRuleIds("dep-none").collectList().block()).isEmpty();
    }

    @Test
    void markRemoved_stampsTheRecord_andKeepsTheRow() {
        DeploymentRouteRuleRepository records = records();
        String kept = newId();
        String removed = newId();
        records.record("dep-a", kept).block();
        records.record("dep-a", removed).block();

        records.markRemoved(removed).block();

        assertThat(records.liveRuleIds("dep-a").collectList().block()).containsExactly(kept);
        // stamped, not deleted: the deployment and the rule are both still known
        assertThat(rowCount()).isEqualTo(2);
        assertThat(records.isRecorded(removed).block()).isTrue();
        assertThat(records.hasEverRecorded("dep-a").block()).isTrue();
    }

    @Test
    void markRemoved_twice_orForAnIdNeverRecorded_changesNothing() {
        DeploymentRouteRuleRepository records = records();
        String id = newId();
        records.record("dep-a", id).block();
        records.markRemoved(id).block();
        List<String> stamps = stamps();

        records.markRemoved(id).block();          // a repeat keeps the first stamp
        records.markRemoved(newId()).block();     // unknown id: no row appears

        assertThat(stamps()).isEqualTo(stamps);
        assertThat(rowCount()).isEqualTo(1);
    }

    private List<String> stamps() {
        return db.sql("SELECT rule_id, removed_at FROM service_deployment_route_rule ORDER BY rule_id")
                .map((row, meta) -> row.get("rule_id", UUID.class) + "@" + row.get("removed_at", java.time.OffsetDateTime.class))
                .all().collectList().block();
    }

    @Test
    void hasEverRecorded_isFalseUntilTheFirstRecord_andStaysTrueOnceEveryRuleIsRemoved() {
        DeploymentRouteRuleRepository records = records();
        String id = newId();
        assertThat(records.hasEverRecorded("dep-a").block()).isFalse();

        records.record("dep-a", id).block();
        assertThat(records.hasEverRecorded("dep-a").block()).isTrue();
        assertThat(records.hasEverRecorded("dep-b").block()).isFalse();

        records.markRemoved(id).block();
        assertThat(records.liveRuleIds("dep-a").collectList().block()).isEmpty();
        assertThat(records.hasEverRecorded("dep-a").block()).isTrue();
    }

    @Test
    void isRecorded_isAboutTheRule_whicheverDeploymentWroteIt() {
        DeploymentRouteRuleRepository records = records();
        String id = newId();
        records.record("dep-a", id).block();

        assertThat(records.isRecorded(id).block()).isTrue();
        assertThat(records.isRecorded(newId()).block()).isFalse();
    }

    @Test
    void aRuleHasOneOwner_recordingItASecondTimeIsRefused() {
        DeploymentRouteRuleRepository records = records();
        String id = newId();
        records.record("dep-a", id).block();

        assertThatThrownBy(() -> records.record("dep-b", id).block())
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);

        assertThat(records.liveRuleIds("dep-a").collectList().block()).containsExactly(id);
        assertThat(records.liveRuleIds("dep-b").collectList().block()).isEmpty();
    }

    // ── the GRANT ────────────────────────────────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({"SELECT,true", "INSERT,true", "UPDATE,true", "DELETE,false", "TRUNCATE,false"})
    void adminbffApp_holdsTheVerbsTheStoreUses_andNoOther(String privilege, boolean expected) {
        Boolean held = db.sql("SELECT has_table_privilege('adminbff_app',"
                        + " 'service_deployment_route_rule', :privilege) AS held")
                .bind("privilege", privilege)
                .map((row, meta) -> row.get("held", Boolean.class)).one().block();

        assertThat(held).isEqualTo(expected);
    }

    @Test
    void everyStatementTheStoreIssues_runsAsAdminbffApp() {
        DeploymentRouteRuleRepository records = records();
        TransactionalOperator tx = EffectorFixture.tx(db);
        String id = newId();
        // SET LOCAL ROLE lasts for this transaction and is on the transaction's own connection,
        // the one every statement below runs on.
        List<Object> seen = new java.util.ArrayList<>();
        Mono<Void> asApp = db.sql("SET LOCAL ROLE adminbff_app").fetch().rowsUpdated()
                .then(records.record("dep-a", id))                                           // INSERT
                .then(records.liveRuleIds("dep-a").collectList().doOnNext(seen::add))        // SELECT
                .then(records.hasEverRecorded("dep-a").doOnNext(seen::add))                  // SELECT
                .then(records.isRecorded(id).doOnNext(seen::add))                            // SELECT
                .then(records.markRemoved(id))                                               // UPDATE
                .then(records.liveRuleIds("dep-a").collectList().doOnNext(seen::add))
                .then();

        asApp.as(tx::transactional).block();

        assertThat(seen).containsExactly(List.of(id), true, true, List.of());
        assertThat(rowCount()).isEqualTo(1);
    }

    @Test
    void theRoleSwitchIsReal_adminbffAppCannotDeleteARecord() {
        // The control for the test above: if SET LOCAL ROLE did not take, that test would pass
        // as the database owner and prove nothing. As adminbff_app a DELETE must be refused.
        DeploymentRouteRuleRepository records = records();
        records.record("dep-a", newId()).block();
        TransactionalOperator tx = EffectorFixture.tx(db);
        Mono<Long> deleteAsApp = db.sql("SET LOCAL ROLE adminbff_app").fetch().rowsUpdated()
                .then(db.sql("DELETE FROM service_deployment_route_rule").fetch().rowsUpdated());

        assertThatThrownBy(() -> deleteAsApp.as(tx::transactional).block())
                .hasMessageContaining("permission denied");

        assertThat(rowCount()).isEqualTo(1);
    }
}
