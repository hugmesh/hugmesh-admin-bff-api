package net.hugmesh.adminbff.golive;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The go_live_intent R2DBC repository over the Liquibase-applied REAL Postgres
 * (Testcontainers, {@link TestDatabaseConfig}) — proves the 270 changelog applies (table +
 * the target_state/status CHECKs + the DB-generated id DEFAULT) and the ledger idiom
 * round-trips: INSERT..RETURNING id, the CAS withdraw single-winner, the monotonic
 * generation floor, and the recorded-only read the signed export compiles from.
 *
 * <p>Mirrors {@code DomainRegistryRepositoryTest} ({@code @DataR2dbcTest}, DELETE-FROM
 * cleanup, {@code R2dbcRepos.of} factory). The INTENT-ONLY invariant is asserted
 * structurally: a fresh insert carries {@code applied_at/applied_by} NULL and status
 * {@code recorded} — no BFF code path ever writes {@code applied} (that CAS belongs to the
 * host agent, in a later leg).
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class GoLiveIntentRepositoryTest {

    private static final String ACTOR = "superadmin@infra";

    @Autowired DatabaseClient db;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM go_live_intent").fetch().rowsUpdated().block();
    }

    private GoLiveIntentRepository repo() {
        return new GoLiveIntentRepository(R2dbcRepos.of(db, GoLiveIntentRowRepository.class));
    }

    @Test
    void insertRecorded_dbGeneratesId_statusRecorded_ackSurfaceEmpty() {
        GoLiveIntentRepository repo = repo();
        GoLiveIntent saved = repo.insertRecorded("acme.example", "public", "tunnel",
                "cloudflare-tunnel", "first go-live", ACTOR, 1L).block();

        assertThat(saved).isNotNull();
        assertThat(saved.id()).isNotBlank();                      // (gen_random_uuid())::text
        assertThat(saved.status()).isEqualTo(GoLiveIntent.STATUS_RECORDED);
        assertThat(saved.targetState()).isEqualTo("public");
        assertThat(saved.exposureModel()).isEqualTo("tunnel");
        assertThat(saved.provider()).isEqualTo("cloudflare-tunnel");
        assertThat(saved.note()).isEqualTo("first go-live");
        assertThat(saved.requestedBySubject()).isEqualTo(ACTOR);
        assertThat(saved.generation()).isEqualTo(1L);
        // INTENT ONLY: the host agent's ack surface is untouched by the BFF insert.
        assertThat(saved.appliedAt()).isNull();
        assertThat(saved.appliedBy()).isNull();
    }

    @Test
    void maxGeneration_zeroOnEmpty_thenTracksTheFloor() {
        GoLiveIntentRepository repo = repo();
        StepVerifier.create(repo.maxGeneration()).expectNext(0L).verifyComplete();
        repo.insertRecorded("a.example", "public", "tunnel", "cloudflare-tunnel",
                null, ACTOR, 3L).block();
        StepVerifier.create(repo.maxGeneration()).expectNext(3L).verifyComplete();
    }

    @Test
    void withdraw_casSingleWinner_flipsStatus_andStampsGeneration() {
        GoLiveIntentRepository repo = repo();
        GoLiveIntent saved = repo.insertRecorded("acme.example", "public", "tunnel",
                "cloudflare-tunnel", null, ACTOR, 1L).block();
        assertThat(saved).isNotNull();

        // First withdraw wins the CAS …
        StepVerifier.create(repo.withdraw(saved.id(), 2L)).expectNext(1L).verifyComplete();
        // … the second loses (already withdrawn — audit rows are never deleted).
        StepVerifier.create(repo.withdraw(saved.id(), 3L)).expectNext(0L).verifyComplete();

        StepVerifier.create(repo.findById(saved.id()))
                .assertNext(i -> {
                    assertThat(i.status()).isEqualTo(GoLiveIntent.STATUS_WITHDRAWN);
                    assertThat(i.generation()).isEqualTo(2L); // the WINNING stamp only
                })
                .verifyComplete();
    }

    @Test
    void markApplied_casSingleWinner_stampsAppliedAtAndAppliedBy() {
        GoLiveIntentRepository repo = repo();
        GoLiveIntent saved = repo.insertRecorded("acme.example", "public", "tunnel",
                "cloudflare-tunnel", null, ACTOR, 1L).block();
        assertThat(saved).isNotNull();

        // First applied-ack (correct id + the row's OWN generation) wins the CAS …
        StepVerifier.create(repo.markApplied(saved.id(), 1L, "node-fp-abc123"))
                .expectNext(1L).verifyComplete();
        // … a retry (idempotent poller) loses: already applied, not 'recorded' any more.
        StepVerifier.create(repo.markApplied(saved.id(), 1L, "node-fp-abc123"))
                .expectNext(0L).verifyComplete();

        StepVerifier.create(repo.findById(saved.id()))
                .assertNext(i -> {
                    assertThat(i.status()).isEqualTo(GoLiveIntent.STATUS_APPLIED);
                    assertThat(i.generation()).isEqualTo(1L); // unchanged by the ack
                    assertThat(i.appliedAt()).isNotNull();
                    assertThat(i.appliedBy()).isEqualTo("node-fp-abc123");
                    assertThat(i.toMap()).containsEntry("applied", true);
                })
                .verifyComplete();
    }

    @Test
    void markApplied_staleGeneration_doesNotMatch_rowStaysRecorded() {
        // A host agent acking against a generation OTHER than the row's own current stamp
        // (e.g. a replayed/stale ack) must not flip the row.
        GoLiveIntentRepository repo = repo();
        GoLiveIntent saved = repo.insertRecorded("acme.example", "public", "tunnel",
                "cloudflare-tunnel", null, ACTOR, 5L).block();
        assertThat(saved).isNotNull();

        StepVerifier.create(repo.markApplied(saved.id(), 4L, "node-fp"))
                .expectNext(0L).verifyComplete();
        StepVerifier.create(repo.findById(saved.id()))
                .assertNext(i -> {
                    assertThat(i.status()).isEqualTo(GoLiveIntent.STATUS_RECORDED);
                    assertThat(i.appliedAt()).isNull();
                    assertThat(i.appliedBy()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void markApplied_supersededIntent_staleAckCannotLandOnTheNewRow() {
        // The CAS-supersede model: withdrawing acme.example's old intent mints a BRAND-NEW id
        // for the replacement. A stale ack naming the OLD id+generation must match zero rows
        // — both because status is no longer 'recorded' AND because id alone never matches the
        // new row — and it must never touch the new (superseding) row either.
        GoLiveIntentRepository repo = repo();
        GoLiveIntent oldIntent = repo.insertRecorded("acme.example", "public", "tunnel",
                "cloudflare-tunnel", null, ACTOR, 1L).block();
        assertThat(oldIntent).isNotNull();
        repo.withdraw(oldIntent.id(), 2L).block();
        GoLiveIntent newIntent = repo.insertRecorded("acme.example", "public", "tunnel",
                "cloudflare-tunnel", null, ACTOR, 3L).block();
        assertThat(newIntent).isNotNull();
        assertThat(newIntent.id()).isNotEqualTo(oldIntent.id());

        // Stale ack for the superseded (old) id+generation — harmless no-op.
        StepVerifier.create(repo.markApplied(oldIntent.id(), 1L, "node-fp"))
                .expectNext(0L).verifyComplete();

        StepVerifier.create(repo.findById(newIntent.id()))
                .assertNext(i -> assertThat(i.status()).isEqualTo(GoLiveIntent.STATUS_RECORDED))
                .verifyComplete();
        StepVerifier.create(repo.findById(oldIntent.id()))
                .assertNext(i -> assertThat(i.status()).isEqualTo(GoLiveIntent.STATUS_WITHDRAWN))
                .verifyComplete();
    }

    @Test
    void markApplied_nonRecordedStatus_withdrawnRowDoesNotMatchEvenWithCorrectGeneration() {
        GoLiveIntentRepository repo = repo();
        GoLiveIntent saved = repo.insertRecorded("acme.example", "public", "tunnel",
                "cloudflare-tunnel", null, ACTOR, 1L).block();
        assertThat(saved).isNotNull();
        repo.withdraw(saved.id(), 2L).block(); // now withdrawn at generation 2

        // Correct id + correct CURRENT generation, but status is 'withdrawn' not 'recorded'.
        StepVerifier.create(repo.markApplied(saved.id(), 2L, "node-fp"))
                .expectNext(0L).verifyComplete();
    }

    @Test
    void findRecorded_excludesWithdrawn_andScopesPerDomain() {
        GoLiveIntentRepository repo = repo();
        GoLiveIntent keep = repo.insertRecorded("beta.example", "public", "tunnel",
                "cloudflare-tunnel", null, ACTOR, 1L).block();
        GoLiveIntent gone = repo.insertRecorded("alpha.example", "internal", null, null,
                null, ACTOR, 2L).block();
        assertThat(keep).isNotNull();
        assertThat(gone).isNotNull();
        repo.withdraw(gone.id(), 3L).block();

        // Recorded-only, natural-key ordered (the export compile source).
        StepVerifier.create(repo.findRecorded())
                .assertNext(i -> assertThat(i.clusterDomain()).isEqualTo("beta.example"))
                .verifyComplete();
        // Per-domain supersede check sees only ITS domain's recorded intent.
        StepVerifier.create(repo.findRecordedForDomain("beta.example"))
                .expectNextCount(1).verifyComplete();
        StepVerifier.create(repo.findRecordedForDomain("alpha.example"))
                .verifyComplete();
        // History (audit) still carries both rows, newest first.
        StepVerifier.create(repo.findAll()).expectNextCount(2).verifyComplete();
    }

    @Test
    void checks_pinTheVocabulary_badTargetStateIsRejectedByTheDb() {
        // Proves the 270 CHECK constraints actually applied (the DB is the last wall even
        // if a future caller bypasses the service validation).
        assertThatThrownBy(() -> db.sql("""
                        INSERT INTO go_live_intent \
                        (cluster_domain, target_state, requested_by_subject, generation) \
                        VALUES ('x.example', 'live', 'someone', 1)""")
                .fetch().rowsUpdated().block())
                .hasMessageContaining("ck_go_live_intent_target_state");
    }
}
