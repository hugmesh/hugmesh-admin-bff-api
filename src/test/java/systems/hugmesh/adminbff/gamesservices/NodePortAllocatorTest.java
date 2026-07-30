package systems.hugmesh.adminbff.gamesservices;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The reserved-pool NodePort allocator over real H2 — proves it picks the lowest free port,
 * skips ports held by non-terminal instances (terminated frees them), and FAILS CLOSED
 * (NodePortExhaustedException) when the pool is full.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class NodePortAllocatorTest {

    @Autowired DatabaseClient db;
    private GameInstanceRepository repo;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM game_instance").fetch().rowsUpdated().block();
        repo = new GameInstanceRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.gamesservices.GameInstanceR2dbcRepository.class));
    }

    /** Insert an active instance and assign it a node_port (occupies a pool slot). */
    private void occupy(String name, int port) {
        GameInstance i = repo.insertPending("brandx", "minetest", name, "u", null).block();
        repo.casState(i.id(), "active", "pending").block();
        repo.assignPortAndConsole(i.id(), port, null).block();
    }

    @Test
    void allocate_emptyPool_returnsPoolStart() {
        NodePortAllocator alloc = new NodePortAllocator(repo, 31000, 31002);
        assertThat(alloc.allocate().block()).isEqualTo(31000);
    }

    @Test
    void allocate_skipsTakenPorts_returnsLowestFree() {
        occupy("a", 31000);
        occupy("b", 31001);
        NodePortAllocator alloc = new NodePortAllocator(repo, 31000, 31002);
        assertThat(alloc.allocate().block()).isEqualTo(31002);
    }

    @Test
    void allocate_terminatedFreesItsPort() {
        GameInstance i = repo.insertPending("brandx", "minetest", "t", "u", null).block();
        repo.casState(i.id(), "active", "pending").block();
        repo.assignPortAndConsole(i.id(), 31000, null).block();
        // Terminate -> the port is no longer in the in-use set.
        repo.casState(i.id(), "terminated", "active").block();
        NodePortAllocator alloc = new NodePortAllocator(repo, 31000, 31002);
        assertThat(alloc.allocate().block()).isEqualTo(31000);
    }

    @Test
    void allocate_exhaustedPool_failsClosed() {
        occupy("a", 31000);
        occupy("b", 31001);
        NodePortAllocator alloc = new NodePortAllocator(repo, 31000, 31001);
        StepVerifier.create(alloc.allocate())
                .expectError(NodePortAllocator.NodePortExhaustedException.class)
                .verify();
    }

    @Test
    void assignPortAndConsole_isCasGuarded_onceOnly() {
        GameInstance i = repo.insertPending("brandx", "minetest", "g", "u", null).block();
        repo.casState(i.id(), "active", "pending").block();
        // First assignment wins (node_port was NULL).
        assertThat(repo.assignPortAndConsole(i.id(), 31000, "/games/servers/minetest/g/").block())
                .isEqualTo(1L);
        // Second is a no-op (node_port no longer NULL) — a concurrent allocator cannot clobber.
        assertThat(repo.assignPortAndConsole(i.id(), 31050, null).block()).isEqualTo(0L);
        assertThat(repo.findById(i.id()).block().nodePort()).isEqualTo(31000);
    }
}
