package systems.hugmesh.adminbff.gamesservices;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.adminbff.lease.LeaderElection;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Lease-gated single-writer instance reconciler over real H2 repos + a recording
 * ConfigMap writer + a toggleable fake leader. Proves the SuspensionExpiryAction-cloned
 * contract: not-leader skips entirely; expiry CASes active->terminated; active instances
 * render into their per-domain ConfigMap; propagation_state is reconciled forward
 * (applied on success, failed on writer failure -> retried).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
// DELETEs the seeded game_server_catalog in @BeforeEach; mark dirty AFTER_CLASS so the
// shared (cached) context is re-seeded for sibling classes (see GamesCatalogServiceTest).
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class GameInstanceReconcilerTest {

    @Autowired DatabaseClient db;

    private GameInstanceRepository repo;
    GameServerCatalogRepository catalog;

    private static final String PINNED = "ghcr.io/org/g@sha256:"
            + "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM game_instance").fetch().rowsUpdated().block();
        db.sql("DELETE FROM game_server_catalog").fetch().rowsUpdated().block();
        repo = new GameInstanceRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.gamesservices.GameInstanceR2dbcRepository.class));
        catalog = new GameServerCatalogRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.gamesservices.GameServerCatalogR2dbcRepository.class));
        // Catalog entries for the slugs the tests use (so ensureExposure can resolve
        // protocol/console_port). udp -> needs a NodePort.
        for (String slug : new String[]{"minetest", "xonotic", "veloren", "mindustry",
                "teeworlds", "openarena"}) {
            catalog.insert(new GameServerCatalogEntry(null, slug, slug, PINNED,
                    "GPL-3.0-or-later", "udp", 30000, 8080, null, true, null, "seed", null), "super").block();
        }
    }

    private NodePortAllocator allocator() {
        return new NodePortAllocator(repo, 31000, 31099);
    }

    private GameInstanceReconciler newReconciler(FakeLeader leader, RecordingWriter writer) {
        return new GameInstanceReconciler(repo, leader, writer, allocator(), catalog,
                "hugmesh-games-instances");
    }

    /** A leader gate we can flip. */
    static final class FakeLeader implements LeaderElection {
        boolean leader;
        FakeLeader(boolean leader) { this.leader = leader; }
        @Override public boolean isLeader() { return leader; }
        @Override public String label() { return "fake(leader=" + leader + ")"; }
    }

    /** Records every render call and can be forced to fail. */
    static final class RecordingWriter implements InstanceConfigMapWriter {
        final List<String> renderedDomains = new ArrayList<>();
        int totalInstancesRendered = 0;
        boolean failNext = false;
        @Override public boolean writeDomainConfigMap(String domain, List<GameInstance> instances) {
            renderedDomains.add(domain);
            totalInstancesRendered += instances.size();
            return !failNext;
        }
        @Override public boolean isReal() { return false; }
    }

    private GameInstance active(String domain, String slug, String name, Instant ending) {
        GameInstance i = repo.insertPending(domain, slug, name, "owner", ending).block();
        repo.casState(i.id(), "active", "pending").block();
        return repo.findById(i.id()).block();
    }

    @Test
    void notLeader_skipsEntirely_noRender_noExpiry() {
        active("brandx", "minetest", "w", Instant.now().minus(1, ChronoUnit.HOURS)); // overdue
        RecordingWriter writer = new RecordingWriter();
        GameInstanceReconciler r = newReconciler(new FakeLeader(false), writer);

        r.runOnce().block();

        assertThat(writer.renderedDomains).isEmpty();
        // The overdue instance is NOT terminated (the loop skipped).
        assertThat(repo.activeByDomain("brandx").collectList().block()).hasSize(1);
    }

    @Test
    void leader_expiresOverdue_andRendersActive() {
        // One overdue (should terminate), one permanent active (should render + stay).
        GameInstance overdue = active("brandx", "xonotic", "old",
                Instant.now().minus(1, ChronoUnit.HOURS));
        active("brandx", "veloren", "live", null);
        RecordingWriter writer = new RecordingWriter();
        GameInstanceReconciler r = newReconciler(new FakeLeader(true), writer);

        r.runOnce().block();

        // Overdue terminated (CAS); permanent still active.
        assertThat(repo.findById(overdue.id()).block().state()).isEqualTo("terminated");
        var stillActive = repo.activeByDomain("brandx").collectList().block();
        assertThat(stillActive).extracting(GameInstance::name).containsExactly("live");
        // Rendered brandx exactly once (after expiry), with the single remaining active.
        assertThat(writer.renderedDomains).containsExactly("brandx");
        assertThat(writer.totalInstancesRendered).isEqualTo(1);
        // propagation_state advanced to applied on the rendered row.
        assertThat(repo.activeByDomain("brandx").collectList().block().get(0).propagationState())
                .isEqualTo("applied");
    }

    @Test
    void writerFailure_marksPropagationFailed_forRetry() {
        active("brandx", "mindustry", "w", null);
        RecordingWriter writer = new RecordingWriter();
        writer.failNext = true;
        GameInstanceReconciler r = newReconciler(new FakeLeader(true), writer);

        r.runOnce().block();

        assertThat(repo.activeByDomain("brandx").collectList().block().get(0).propagationState())
                .isEqualTo("failed");
    }

    @Test
    void rendersEveryDomainWithActiveInstances() {
        active("brandx", "teeworlds", "a", null);
        active("brandy", "openarena", "b", null);
        RecordingWriter writer = new RecordingWriter();
        GameInstanceReconciler r = newReconciler(new FakeLeader(true), writer);

        r.runOnce().block();

        assertThat(writer.renderedDomains).containsExactlyInAnyOrder("brandx", "brandy");
    }
}
