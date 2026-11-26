package net.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;
import net.hugmesh.adminbff.web.dto.CreateDomainRequest;
import net.hugmesh.commons.web.ApiException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The two band-190 / decision-29 WRITERS this lane adds, over the real Liquibase-applied Postgres:
 *
 * <ul>
 *   <li><b>reconcile-ack</b> (decision 89b, #6 item 3): advances {@code last_reconciled_generation}
 *       monotonically, ignores a stale or equal one, 404s an unknown domain, and never writes
 *       {@code ca_provisioned} (decision 87a = B);</li>
 *   <li><b>allocate-now</b> (decision 89c, #6 item 5): turns a pre-decision-29 row (NULL pair,
 *       NULL slug) into a provisionable one, refuses a second call with 409, refuses to rename a
 *       slug that is already set, and draws the pair from the same allocator as an insert.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DomainRegistryAckAndAllocateTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM domain_registry").fetch().rowsUpdated().block();
    }

    private DomainRegistryRepository repo() {
        return new DomainRegistryRepository(R2dbcRepos.of(db, DomainRegistryRowRepository.class));
    }

    private DomainRegistryService svc() {
        return new DomainRegistryService(repo());
    }

    private DomainRegistration register(String clusterDomain, String slug) {
        return svc().create(new CreateDomainRequest(clusterDomain, slug, "Org", null, slug, null,
                null, null, null, null, null), "s@infra").block();
    }

    /** A row exactly as one registered BEFORE decision 29 looks: no slug, no MCS pair. */
    private void insertPreDecisionRow(String clusterDomain, String nsPrefix) {
        var spec = db.sql("INSERT INTO domain_registry (id, cluster_domain, brand, ns_prefix, enabled, "
                        + "created_at, updated_at) VALUES (:id, :d, 'legacy', :ns, true, now(), now())")
                .bind("id", java.util.UUID.randomUUID().toString())
                .bind("d", clusterDomain);
        spec = nsPrefix == null ? spec.bindNull("ns", String.class) : spec.bind("ns", nsPrefix);
        spec.fetch().rowsUpdated().block();
    }

    private Map<String, Object> row(String clusterDomain) {
        return db.sql("SELECT * FROM domain_registry WHERE cluster_domain = :d")
                .bind("d", clusterDomain).fetch().one().block();
    }

    private static int status(Throwable e) {
        return ((ApiException) e).status().value();
    }

    // ── reconcile-ack ───────────────────────────────────────────────────────────────

    @Test
    void ack_knownDomain_advancesGeneration_andAppset_butNeverCaProvisioned() {
        register("acme.test", "acme");
        assertThat(svc().recordReconcileAck("acme.test", true, 5L).block()).isTrue();
        Map<String, Object> r = row("acme.test");
        assertThat(((Number) r.get("last_reconciled_generation")).longValue()).isEqualTo(5L);
        assertThat(r.get("appset_registered")).isEqualTo(true);
        assertThat(r.get("ca_provisioned")).as("decision 87a = B: never written by a node ack")
                .isEqualTo(false);
    }

    @Test
    void ack_isMonotonic_staleAndEqualGenerationsAreIgnored() {
        register("acme.test", "acme");
        DomainRegistryService svc = svc();
        assertThat(svc.recordReconcileAck("acme.test", true, 5L).block()).isTrue();
        // An older ack arriving late must not walk the generation back, nor flip appset.
        assertThat(svc.recordReconcileAck("acme.test", false, 3L).block()).isFalse();
        // An equal one is a replay: also a no-op.
        assertThat(svc.recordReconcileAck("acme.test", false, 5L).block()).isFalse();
        Map<String, Object> r = row("acme.test");
        assertThat(((Number) r.get("last_reconciled_generation")).longValue()).isEqualTo(5L);
        assertThat(r.get("appset_registered")).isEqualTo(true);
        // A newer one moves it on.
        assertThat(svc.recordReconcileAck("acme.test", false, 6L).block()).isTrue();
        assertThat(((Number) row("acme.test").get("last_reconciled_generation")).longValue())
                .isEqualTo(6L);
        assertThat(row("acme.test").get("appset_registered")).isEqualTo(false);
    }

    @Test
    void ack_unknownDomain_is404_andWritesNothing() {
        register("acme.test", "acme");
        assertThatThrownBy(() -> svc().recordReconcileAck("ghost.test", true, 9L).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(404));
        assertThat(((Number) row("acme.test").get("last_reconciled_generation")).longValue())
                .isZero();
    }

    @Test
    void ack_advancesTheExportGeneration() {
        register("acme.test", "acme");
        svc().recordReconcileAck("acme.test", true, 41L).block();
        var body = DomainRegistryExportService.compile("fp", repo().findAll().collectList().block());
        assertThat(body.generation()).as("max(row gen) + 1").isEqualTo(42L);
        assertThat(body.entries().get(0).appsetRegistered()).isTrue();
        assertThat(body.entries().get(0).caProvisioned()).isFalse();
    }

    // ── allocate-now ────────────────────────────────────────────────────────────────

    @Test
    void allocateNow_preDecisionRow_becomesProvisionable_withAFreshPair() {
        DomainRegistration live = register("live.test", "live");   // takes slot 0
        insertPreDecisionRow("legacy.test", null);

        DomainRegistration fixed = svc().allocateNow("legacy.test", "legacy", "sa@infra").block();

        assertThat(fixed).isNotNull();
        assertThat(fixed.nsPrefix()).isEqualTo("legacy");
        assertThat(fixed.selinuxLevel()).isEqualTo("s0:c258");
        assertThat(fixed.selinuxLevelPg()).isEqualTo("s0:c259");
        assertThat(fixed.selinuxLevel()).isNotEqualTo(live.selinuxLevel());
        // Nothing else about the row moved.
        assertThat(fixed.brand()).isEqualTo("legacy");
        assertThat(fixed.enabled()).isTrue();
        // It is now a complete export entry.
        var entry = DomainRegistryExportService.compile("fp", repo().findAll().collectList().block())
                .entries().stream().filter(e -> e.clusterDomain().equals("legacy.test")).findFirst()
                .orElseThrow();
        assertThat(entry.nsPrefix()).isEqualTo("legacy");
        assertThat(entry.selinuxLevel()).isEqualTo("s0:c258");
    }

    @Test
    void allocateNow_secondCall_is409_andChangesNothing() {
        insertPreDecisionRow("legacy.test", null);
        DomainRegistryService svc = svc();
        DomainRegistration first = svc.allocateNow("legacy.test", "legacy", "sa@infra").block();
        assertThatThrownBy(() -> svc.allocateNow("legacy.test", "legacy", "sa@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(409))
                .hasMessageContaining("nothing to allocate");
        DomainRegistration after = svc.get("legacy.test").block();
        assertThat(after.selinuxLevel()).isEqualTo(first.selinuxLevel());
        assertThat(after.nsPrefix()).isEqualTo("legacy");
    }

    @Test
    void allocateNow_slugAlreadySet_refusesARename_butAllocatesThePair() {
        insertPreDecisionRow("legacy.test", "kept");
        DomainRegistryService svc = svc();
        assertThatThrownBy(() -> svc.allocateNow("legacy.test", "other", "sa@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(409))
                // Named, so the refusal is the immutability rule and not merely the CAS backstop.
                .hasMessageContaining("nsPrefix is immutable");
        assertThat(svc.get("legacy.test").block().selinuxLevel())
                .as("the refused call allocated nothing").isNull();

        DomainRegistration fixed = svc.allocateNow("legacy.test", null, "sa@infra").block();
        assertThat(fixed.nsPrefix()).isEqualTo("kept");
        assertThat(fixed.selinuxLevel()).isEqualTo("s0:c256");
        assertThat(fixed.selinuxLevelPg()).isEqualTo("s0:c257");
    }

    @Test
    void allocateNow_slugLessRow_withoutASlug_is400() {
        insertPreDecisionRow("legacy.test", null);
        assertThatThrownBy(() -> svc().allocateNow("legacy.test", null, "sa@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
        assertThatThrownBy(() -> svc().allocateNow("legacy.test", "Not_A_Label", "sa@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
        assertThat(row("legacy.test").get("selinux_level")).isNull();
    }

    @Test
    void allocateNow_slugTakenByAnotherDomain_is409() {
        register("live.test", "live");
        insertPreDecisionRow("legacy.test", null);
        assertThatThrownBy(() -> svc().allocateNow("legacy.test", "live", "sa@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(409));
        assertThat(row("legacy.test").get("ns_prefix")).isNull();
        assertThat(row("legacy.test").get("selinux_level")).isNull();
    }

    @Test
    void allocateNow_slugOnlyMissing_setsTheSlug_keepsThePair() {
        // A row with a pair but no slug (possible: 29c allocated at insert, 29a's required-slug
        // check came with it, but a hand-written row can still look like this).
        db.sql("INSERT INTO domain_registry (id, cluster_domain, enabled, created_at, updated_at, "
                        + "selinux_level, selinux_level_pg) VALUES ('x-1', 'half.test', true, now(), "
                        + "now(), 's0:c300', 's0:c301')")
                .fetch().rowsUpdated().block();
        DomainRegistration fixed = svc().allocateNow("half.test", "half", "sa@infra").block();
        assertThat(fixed.nsPrefix()).isEqualTo("half");
        assertThat(fixed.selinuxLevel()).isEqualTo("s0:c300");
        assertThat(fixed.selinuxLevelPg()).isEqualTo("s0:c301");
    }

    @Test
    void allocateNow_halfAPair_is409() {
        db.sql("INSERT INTO domain_registry (id, cluster_domain, enabled, created_at, updated_at, "
                        + "selinux_level) VALUES ('x-2', 'odd.test', true, now(), now(), 's0:c300')")
                .fetch().rowsUpdated().block();
        assertThatThrownBy(() -> svc().allocateNow("odd.test", "odd", "sa@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(409));
    }

    @Test
    void allocateNow_unknownDomain_is404() {
        assertThatThrownBy(() -> svc().allocateNow("ghost.test", "ghost", "sa@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(404));
    }

    // ── found while writing this: a pre-decision row broke EVERY registration ────────

    @Test
    void create_whileAPreDecisionRowExists_stillAllocates() {
        // On origin/main d5b065c this was a 500: the allocator's taken-set read mapped each row
        // to its selinux_level BEFORE filtering nulls, and Reactor's map() refuses a null.
        insertPreDecisionRow("legacy.test", null);
        DomainRegistration saved = register("new.test", "fresh");
        assertThat(saved.selinuxLevel()).isEqualTo("s0:c256");
        assertThat(saved.selinuxLevelPg()).isEqualTo("s0:c257");
    }
}
