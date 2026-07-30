package systems.hugmesh.adminbff.mfa;
import systems.hugmesh.authcore.mfa.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.adminbff.testutil.R2dbcRepos;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The durable, multi-replica-safe {@link WebAuthnChallengeStore} over a Liquibase-applied H2
 * (changeset 152). Proves the GO-LIVE property the in-memory ConcurrentHashMap could not give:
 * a challenge issued by ONE store instance is consumable by a SECOND instance sharing the same
 * DB (the multi-replica simulation). Also pins the preserved semantics: short-TTL expiry
 * rejection, atomic single-use (a second consume / replay loses), and owner-subject + ceremony
 * isolation (subject A's challenge is never consumable for subject B).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class WebAuthnChallengeStoreTest {

    @Autowired DatabaseClient db;

    private WebAuthnChallengeR2dbcRepository repo;
    private WebAuthnChallengeStore storeA;
    private WebAuthnChallengeStore storeB;

    @BeforeEach
    void setup() {
        db.sql("DELETE FROM webauthn_challenge").fetch().rowsUpdated().block();
        repo = R2dbcRepos.of(db, WebAuthnChallengeR2dbcRepository.class);
        // TWO independent store instances over the SAME DB — the multi-replica simulation.
        storeA = new WebAuthnChallengeStore(repo);
        storeB = new WebAuthnChallengeStore(repo);
    }

    @Test
    void challengeIssuedOnOneReplica_isConsumableOnAnother_multiReplica() {
        storeA.put("alice", WebAuthnChallengeStore.PURPOSE_REGISTER, "chal-A").block();

        // A DIFFERENT replica's store instance consumes the SAME DB-backed challenge.
        String consumed = storeB.consume("alice", WebAuthnChallengeStore.PURPOSE_REGISTER).block();
        assertThat(consumed).isEqualTo("chal-A");
    }

    @Test
    void singleUse_secondConsumeFails() {
        storeA.put("alice", WebAuthnChallengeStore.PURPOSE_ASSERT, "chal-once").block();

        assertThat(storeA.consume("alice", WebAuthnChallengeStore.PURPOSE_ASSERT).block())
                .isEqualTo("chal-once");
        // A replay / second concurrent verify against the same challenge finds nothing.
        assertThat(storeB.consume("alice", WebAuthnChallengeStore.PURPOSE_ASSERT).block())
                .isNull();
    }

    @Test
    void expiredChallenge_isRejected() {
        // Insert a row directly with an already-past expires_at (the put TTL is ~5m).
        repo.save(new WebAuthnChallengeRow(UUID.randomUUID().toString(), "alice", "chal-stale",
                WebAuthnChallengeStore.PURPOSE_REGISTER, Instant.now().minusSeconds(60), false,
                Instant.now().minusSeconds(360), true)).block();

        assertThat(storeA.consume("alice", WebAuthnChallengeStore.PURPOSE_REGISTER).block())
                .isNull();
    }

    @Test
    void crossOwnerIsolation_ownerAChallengeNotConsumableForOwnerB() {
        storeA.put("alice", WebAuthnChallengeStore.PURPOSE_ASSERT, "alice-chal").block();

        // bob cannot consume alice's challenge.
        assertThat(storeB.consume("bob", WebAuthnChallengeStore.PURPOSE_ASSERT).block())
                .isNull();
        // alice's challenge is still intact (bob's miss did not consume it).
        assertThat(storeA.consume("alice", WebAuthnChallengeStore.PURPOSE_ASSERT).block())
                .isEqualTo("alice-chal");
    }

    @Test
    void crossCeremonyIsolation_registerChallengeNotConsumableAsAssert() {
        storeA.put("alice", WebAuthnChallengeStore.PURPOSE_REGISTER, "reg-chal").block();

        // a REGISTER challenge is not consumable under the ASSERT ceremony.
        assertThat(storeA.consume("alice", WebAuthnChallengeStore.PURPOSE_ASSERT).block())
                .isNull();
        assertThat(storeA.consume("alice", WebAuthnChallengeStore.PURPOSE_REGISTER).block())
                .isEqualTo("reg-chal");
    }

    @Test
    void reissue_supersedesPriorPendingChallenge() {
        storeA.put("alice", WebAuthnChallengeStore.PURPOSE_REGISTER, "old-chal").block();
        // A fresh options call supersedes the prior pending challenge (prune-then-insert).
        storeA.put("alice", WebAuthnChallengeStore.PURPOSE_REGISTER, "new-chal").block();

        assertThat(storeB.consume("alice", WebAuthnChallengeStore.PURPOSE_REGISTER).block())
                .isEqualTo("new-chal");
        // exactly one row was consumable; the superseded one is gone.
        assertThat(storeB.consume("alice", WebAuthnChallengeStore.PURPOSE_REGISTER).block())
                .isNull();
    }

    @Test
    void blankSubject_isNoOp() {
        assertThat(storeA.put("", WebAuthnChallengeStore.PURPOSE_REGISTER, "x").block()).isNull();
        assertThat(storeA.consume("", WebAuthnChallengeStore.PURPOSE_REGISTER).block()).isNull();
        assertThat(repo.count().block()).isEqualTo(0L);
    }
}
