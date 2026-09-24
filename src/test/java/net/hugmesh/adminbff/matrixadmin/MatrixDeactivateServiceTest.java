package net.hugmesh.adminbff.matrixadmin;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.matrixadmin.MatrixDeactivateService.Refusal;
import net.hugmesh.adminbff.matrixadmin.MatrixDeactivateService.RefusedException;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;
import net.hugmesh.adminbff.testutil.R2dbcRepos;

/**
 * Decision 83a = C, end to end over the REAL Liquibase-applied Postgres (changeset 370) and the
 * real transport against a stub tuwunel: propose mints a token bound to (mxid, admin subject);
 * confirm deactivates only inside the window, once, for that account, by that admin.
 *
 * <p>Every refusal also asserts the one thing that matters for a one-way door: NO command was
 * sent to the admin room.
 */
@SpringBootTest(classes = MatrixDeactivateServiceTest.Boot.class)
@ActiveProfiles("test")
class MatrixDeactivateServiceTest extends AdminBffPostgresTestSupport {

    // No @ComponentScan: only the DatabaseClient over the per-class Postgres is needed.
    // A plain @Configuration, NOT @SpringBootConfiguration: Boot's configuration search walks
    // the package, and a discoverable nested boot class here would become the context of
    // every slice test in this package (it emptied MatrixAdminDeactivateControllerTest's
    // routing table — every request 404'd).
    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @org.springframework.boot.autoconfigure.EnableAutoConfiguration
    static class Boot { }

    private static final Duration TTL = Duration.ofMinutes(2);
    private static final String ALICE_ADMIN = "admin-alice-subject";
    private static final String BOB_ADMIN = "admin-bob-subject";

    @Autowired DatabaseClient db;

    private MutableClock clock;
    private TuwunelStub tuwunel;
    private MatrixDeactivateProposalRepository repo;

    /** A Clock the test can move, so "expired" needs no sleep. */
    static final class MutableClock extends Clock {
        private final AtomicReference<Instant> now;

        MutableClock(Instant start) {
            this.now = new AtomicReference<>(start);
        }

        void advance(Duration d) {
            now.updateAndGet(i -> i.plus(d));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.now());
        tuwunel = new TuwunelStub();
        repo = R2dbcRepos.of(db, MatrixDeactivateProposalRepository.class);
        // One database per test CLASS: start every method from an empty table.
        db.sql("DELETE FROM matrix_admin_deactivate_proposal").then().block();
    }

    private MatrixDeactivateService service(boolean enabled) {
        MatrixAdminDeactivateClient client = new MatrixAdminDeactivateClient(tuwunel.webClient(), enabled,
                "vault-injected-admin-token", "hugmesh.net", "#admins:hugmesh.net", Duration.ofSeconds(2));
        return new MatrixDeactivateService(repo, client, TTL, clock);
    }

    private static Refusal refusalOf(Mono<?> call) {
        try {
            call.block();
        } catch (RefusedException e) {
            return e.refusal();
        }
        throw new AssertionError("expected the confirm to be refused, but it went through");
    }

    // ── happy path ────────────────────────────────────────────────────────────────

    @Test
    void proposeThenConfirm_insideTheWindow_postsTheDeactivate_andRecordsTheOutcome() {
        MatrixDeactivateService svc = service(true);

        MatrixDeactivateService.Proposal p = svc.propose(ALICE_ADMIN, "@victim:hugmesh.net").block();
        assertThat(p.mxid()).isEqualTo("@victim:hugmesh.net");
        assertThat(p.ttlSeconds()).isEqualTo(120);
        assertThat(p.token()).hasSizeGreaterThanOrEqualTo(43); // 32 random bytes, base64url
        // Proposing sends NOTHING.
        assertThat(tuwunel.seen).isEmpty();

        clock.advance(Duration.ofSeconds(119));
        MatrixDeactivateService.Confirmation c = svc.confirm(ALICE_ADMIN, "@victim:hugmesh.net", p.token()).block();

        assertThat(c.outcome()).isEqualTo(MatrixAdminOutcome.posted("$evt-1"));
        assertThat(tuwunel.sends()).singleElement()
                .satisfies(s -> assertThat(s.body()).contains("!admin users deactivate @victim:hugmesh.net\""));

        MatrixDeactivateProposalRow row = repo.findById(p.proposalId()).block();
        assertThat(row.state()).isEqualTo("confirmed");
        assertThat(row.confirmedAt()).isNotNull();
        assertThat(row.outcome()).isEqualTo("posted:$evt-1");
        assertThat(row.proposedBy()).isEqualTo(ALICE_ADMIN);
    }

    @Test
    void theRawTokenIsNeverStored_onlyItsHash() {
        MatrixDeactivateService.Proposal p = service(true).propose(ALICE_ADMIN, "victim").block();

        List<Map<String, Object>> rows = db.sql("SELECT * FROM matrix_admin_deactivate_proposal WHERE id = :id")
                .bind("id", p.proposalId()).fetch().all().collectList().block();
        assertThat(rows).singleElement().satisfies(r -> {
            assertThat(r.values()).doesNotContain(p.token());
            assertThat(r.get("token_hash")).isEqualTo(MatrixDeactivateService.sha256(p.token()));
        });
    }

    // ── the five refusals + confirm-without-propose (decision 83a done-when) ─────────

    @Test
    void refused_noToken() {
        MatrixDeactivateService svc = service(true);
        svc.propose(ALICE_ADMIN, "victim").block();

        assertThat(refusalOf(svc.confirm(ALICE_ADMIN, "victim", null))).isEqualTo(Refusal.NO_TOKEN);
        assertThat(refusalOf(svc.confirm(ALICE_ADMIN, "victim", "   "))).isEqualTo(Refusal.NO_TOKEN);
        assertThat(tuwunel.seen).isEmpty();
    }

    @Test
    void refused_confirmWithoutPropose() {
        MatrixDeactivateService svc = service(true);

        // A well-formed token nobody ever minted.
        assertThat(refusalOf(svc.confirm(ALICE_ADMIN, "victim", "A".repeat(43))))
                .isEqualTo(Refusal.UNKNOWN_TOKEN);
        assertThat(tuwunel.seen).isEmpty();
    }

    @Test
    void refused_expiredToken() {
        MatrixDeactivateService svc = service(true);
        MatrixDeactivateService.Proposal p = svc.propose(ALICE_ADMIN, "victim").block();

        clock.advance(TTL); // exactly at expiry is already outside the window
        assertThat(refusalOf(svc.confirm(ALICE_ADMIN, "victim", p.token()))).isEqualTo(Refusal.EXPIRED);
        clock.advance(Duration.ofHours(1));
        assertThat(refusalOf(svc.confirm(ALICE_ADMIN, "victim", p.token()))).isEqualTo(Refusal.EXPIRED);
        assertThat(tuwunel.seen).isEmpty();
        assertThat(repo.findById(p.proposalId()).block().state()).isEqualTo("proposed");
    }

    @Test
    void refused_reusedToken_theSecondConfirmSendsNothing() {
        MatrixDeactivateService svc = service(true);
        MatrixDeactivateService.Proposal p = svc.propose(ALICE_ADMIN, "victim").block();

        svc.confirm(ALICE_ADMIN, "victim", p.token()).block();
        assertThat(refusalOf(svc.confirm(ALICE_ADMIN, "victim", p.token()))).isEqualTo(Refusal.ALREADY_USED);

        assertThat(tuwunel.sends()).hasSize(1);
    }

    @Test
    void refused_tokenForAnotherAccount() {
        MatrixDeactivateService svc = service(true);
        MatrixDeactivateService.Proposal p = svc.propose(ALICE_ADMIN, "@victim:hugmesh.net").block();

        assertThat(refusalOf(svc.confirm(ALICE_ADMIN, "@bystander:hugmesh.net", p.token())))
                .isEqualTo(Refusal.OTHER_ACCOUNT);
        assertThat(tuwunel.seen).isEmpty();
    }

    @Test
    void refused_tokenMintedByAnotherAdmin() {
        MatrixDeactivateService svc = service(true);
        MatrixDeactivateService.Proposal p = svc.propose(ALICE_ADMIN, "victim").block();

        assertThat(refusalOf(svc.confirm(BOB_ADMIN, "victim", p.token()))).isEqualTo(Refusal.OTHER_ADMIN);
        assertThat(tuwunel.seen).isEmpty();
    }

    @Test
    void aRefusalDoesNotSpendTheToken_theProposingAdminCanStillConfirm() {
        MatrixDeactivateService svc = service(true);
        MatrixDeactivateService.Proposal p = svc.propose(ALICE_ADMIN, "victim").block();

        refusalOf(svc.confirm(BOB_ADMIN, "victim", p.token()));
        refusalOf(svc.confirm(ALICE_ADMIN, "bystander", p.token()));

        assertThat(svc.confirm(ALICE_ADMIN, "victim", p.token()).block().outcome().isPosted()).isTrue();
        assertThat(tuwunel.sends()).hasSize(1);
    }

    // ── single use across replicas ────────────────────────────────────────────────

    @Test
    void concurrentConfirms_exactlyOneWins() {
        MatrixDeactivateService svc = service(true);
        MatrixDeactivateService.Proposal p = svc.propose(ALICE_ADMIN, "victim").block();

        // Many confirms racing on the same token — as two replicas would each receive one.
        List<Object> results = reactor.core.publisher.Flux.range(0, 8)
                .flatMap(i -> svc.confirm(ALICE_ADMIN, "victim", p.token())
                        .<Object>map(c -> c)
                        .onErrorResume(RefusedException.class, e -> Mono.just(e.refusal()))
                        .subscribeOn(Schedulers.parallel()))
                .collectList().block();

        assertThat(results.stream().filter(r -> r instanceof MatrixDeactivateService.Confirmation)).hasSize(1);
        assertThat(results.stream().filter(r -> r == Refusal.ALREADY_USED)).hasSize(7);
        assertThat(tuwunel.sends()).hasSize(1);
    }

    // ── dark, bad target, degraded transport ───────────────────────────────────────

    @Test
    void dark_proposeAndConfirmBothRefuse_andWriteNothing() {
        MatrixDeactivateService svc = service(false);

        assertThat(svc.propose(ALICE_ADMIN, "victim").onErrorResume(MatrixDeactivateService.DarkException.class,
                e -> Mono.empty()).block()).isNull();
        assertThat(svc.confirm(ALICE_ADMIN, "victim", "A".repeat(43)).onErrorResume(
                MatrixDeactivateService.DarkException.class, e -> Mono.empty()).block()).isNull();

        assertThat(repo.count().block()).isZero();
        assertThat(tuwunel.seen).isEmpty();
    }

    @Test
    void aTargetThatIsNotAPlainMxid_isRejectedAtPropose_andNothingIsRecorded() {
        MatrixDeactivateService svc = service(true);

        assertThat(svc.propose(ALICE_ADMIN, "victim --no-leave-rooms")
                .onErrorResume(MatrixDeactivateService.BadTargetException.class, e -> Mono.empty())
                .block()).isNull();
        assertThat(repo.count().block()).isZero();
    }

    @Test
    void aDegradedPost_spendsTheToken_andRecordsTheDegradedOutcome() {
        MatrixDeactivateService svc = service(true);
        MatrixDeactivateService.Proposal p = svc.propose(ALICE_ADMIN, "victim").block();
        tuwunel.sendStatus = org.springframework.http.HttpStatus.BAD_GATEWAY;

        MatrixDeactivateService.Confirmation c = svc.confirm(ALICE_ADMIN, "victim", p.token()).block();

        assertThat(c.outcome()).isEqualTo(MatrixAdminOutcome.degraded("http-502"));
        assertThat(repo.findById(p.proposalId()).block().outcome()).isEqualTo("degraded:http-502");
        // Spent: a retry must go back through propose.
        tuwunel.sendStatus = org.springframework.http.HttpStatus.OK;
        assertThat(refusalOf(svc.confirm(ALICE_ADMIN, "victim", p.token()))).isEqualTo(Refusal.ALREADY_USED);
    }

    @Test
    void theConfiguredWindowMustBeShortLived() {
        assertThat(MatrixAdminConfig.checkedTtl(Duration.ofMinutes(2))).isEqualTo(Duration.ofMinutes(2));
        for (Duration bad : new Duration[] {Duration.ZERO, Duration.ofSeconds(-1), Duration.ofMinutes(16), null}) {
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> MatrixAdminConfig.checkedTtl(bad))
                    .as(String.valueOf(bad)).isInstanceOf(IllegalStateException.class);
        }
    }
}
