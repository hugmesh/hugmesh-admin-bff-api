package systems.hugmesh.adminbff.notification;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.lease.AlwaysLeader;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The Notifications PR4 part-B ENGINE proven over a REAL H2 (PG-compat) with the
 * production Liquibase changelog applied (the 062 notification spine tables) and the
 * user-bff client MOCKED. The {@link NotificationReconciler} is the FIRST writer of
 * {@code notification_delivery} + {@code notification_cursor} (PR2 shipped them dark).
 *
 * <p>Delineated:
 * <ul>
 *   <li>HAPPY — an account-restriction outbox row -> exactly ONE user-bff deliver call
 *       carrying the right (domain, userSubject, category) + a
 *       {@code notification_delivery(in-app, sent)} row.</li>
 *   <li>NEUTRAL — the call's title/body are impersonal and never carry an actor.</li>
 *   <li>IDEMPOTENT — a re-tick over an already-delivered row makes NO second call + NO
 *       second delivery row (UNIQUE(outbox_id, channel)).</li>
 *   <li>FAILURE — a transport failure records NO delivery, does NOT advance the cursor
 *       past the row, and the row is RETRIED next tick.</li>
 *   <li>NEVER-HARD-FAIL / poison — a row whose call keeps failing is retried then
 *       DEAD-LETTERED (a 'failed' delivery) after N attempts; it never crashes the tick
 *       nor wedges the cursor (a later good row still delivers).</li>
 *   <li>IN-APP ONLY — the only external collaborator invoked is the user-bff client;
 *       there is no Matrix/Akkoma/email path here.</li>
 *   <li>AUTH — the outbound call is carried by the part-A ROLE_SERVICE client_credentials
 *       Bearer mechanism (asserted at the config/client level in
 *       {@link UserBffNotificationClientAuthTest}).</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
// A unique property forces a DISTINCT cached test context (hence a DISTINCT H2 mem DB,
// since TestDatabaseConfig names the store per-context) so this class — which writes
// notification_cursor / notification_delivery rows — never shares a store with another
// @DataR2dbcTest (e.g. SuspensionOutboxTransactionTest's "ships dark" assertions).
@org.springframework.test.context.TestPropertySource(properties =
        "test.context.key=notification-reconciler")
class NotificationReconcilerTest {

    @Autowired DatabaseClient db;

    private NotificationDeliveryRepository deliveries;
    private NotificationCursorRepository cursor;
    private NotificationOutboxRepository outbox;
    private UserBffNotificationClient userBff;
    private MeterRegistry meters;
    private NotificationReconciler reconciler;

    @BeforeEach
    void setup() {
        db.sql("DELETE FROM notification_delivery").fetch().rowsUpdated().block();
        db.sql("DELETE FROM notification_cursor").fetch().rowsUpdated().block();
        db.sql("DELETE FROM notification_outbox").fetch().rowsUpdated().block();

        deliveries = new NotificationDeliveryRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.notification.NotificationDeliveryR2dbcRepository.class));
        cursor = new NotificationCursorRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.notification.NotificationCursorR2dbcRepository.class));
        outbox = new NotificationOutboxRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository.class));
        userBff = mock(UserBffNotificationClient.class);
        meters = new SimpleMeterRegistry();
        // batch 100, maxAttempts 3 (so the poison test exhausts quickly).
        reconciler = new NotificationReconciler(deliveries, cursor, userBff,
                new AlwaysLeader(), meters, 100, 3);
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    /** Insert an account-restriction outbox row (target=userSubject) and return its id. */
    private String seedRestriction(String domain, String userSubject, Long ttl, String reason) {
        String sourceId = UUID.randomUUID().toString();
        String payload = AccountRestrictionPayload.build(userSubject, "PROFILE", ttl, reason);
        outbox.insert(domain, NotificationOutbox.SOURCE_ACCESS_SUSPENSION, sourceId,
                NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION, payload).block();
        return outbox.findBySource(NotificationOutbox.SOURCE_ACCESS_SUSPENSION, sourceId,
                NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION).block().id();
    }

    private long countOf(String table) {
        Long c = db.sql("SELECT count(*) AS c FROM " + table)
                .map((row, meta) -> row.get("c", Long.class)).first().block();
        return c == null ? 0 : c;
    }

    private double metric(String name) {
        var m = meters.find(name).counter();
        return m == null ? 0d : m.count();
    }

    // ── HAPPY: one deliver call with the right fields + a sent delivery row ──
    @Test
    void accountRestriction_deliversOnce_andRecordsSentDelivery() {
        when(userBff.deliverInApp(any()))
                .thenReturn(Mono.just(UserBffNotificationClient.Outcome.DELIVERED));
        String outboxId = seedRestriction("brandx", "subject-alice", 3600L, "abuse");

        reconciler.runOnce().block();

        var captor = forClass(UserBffNotification.class);
        verify(userBff, times(1)).deliverInApp(captor.capture());
        UserBffNotification sent = captor.getValue();
        assertThat(sent.domain()).isEqualTo("brandx");
        assertThat(sent.userSubject()).isEqualTo("subject-alice");
        assertThat(sent.category()).isEqualTo("account-restriction");
        assertThat(sent.sourceTable()).isEqualTo(NotificationOutbox.SOURCE_ACCESS_SUSPENSION);

        // exactly one in-app delivery row, status sent.
        assertThat(countOf("notification_delivery")).isEqualTo(1);
        assertThat(deliveries.existsInApp(outboxId).block()).isTrue();
        assertThat(deliveries.statusInApp(outboxId).block())
                .isEqualTo(NotificationDeliveryRepository.STATUS_SENT);
        assertThat(metric("notification.reconcile.delivered")).isEqualTo(1d);
    }

    // ── NEUTRAL: the composed message never carries an actor identity ───────
    @Test
    void deliveredMessage_isNeutral_neverCarriesAnActor() {
        when(userBff.deliverInApp(any()))
                .thenReturn(Mono.just(UserBffNotificationClient.Outcome.DELIVERED));
        // The outbox payload (by PR2 invariant) has no actor; assert the rendered body
        // is impersonal and reflects the temporary ttl, not who acted.
        seedRestriction("brandx", "subject-bob", 7200L, "spam");

        reconciler.runOnce().block();

        var captor = forClass(UserBffNotification.class);
        verify(userBff).deliverInApp(captor.capture());
        UserBffNotification sent = captor.getValue();
        assertThat(sent.title()).isEqualTo("Your account access changed");
        assertThat(sent.body()).doesNotContain("mod").doesNotContain("actor").doesNotContain("set_by");
        // temporary restriction is surfaced (2 hours) without leaking an identity.
        assertThat(sent.body()).contains("temporary");
    }

    // ── IDEMPOTENT: a re-tick over a delivered row -> no 2nd call / 2nd row ──
    @Test
    void reTickOverDeliveredRow_makesNoSecondCall_andNoSecondDeliveryRow() {
        when(userBff.deliverInApp(any()))
                .thenReturn(Mono.just(UserBffNotificationClient.Outcome.DELIVERED));
        seedRestriction("brandx", "subject-carol", null, "abuse");

        reconciler.runOnce().block();
        reconciler.runOnce().block(); // second tick

        // The LEFT JOIN ... IS NULL no longer selects the delivered row, so no 2nd call.
        verify(userBff, times(1)).deliverInApp(any());
        assertThat(countOf("notification_delivery")).isEqualTo(1);
    }

    // ── FAILURE: no delivery row, cursor not advanced, retried next tick ────
    @Test
    void callFailure_recordsNoDelivery_doesNotAdvanceCursor_retriedNextTick() {
        // First tick fails, second tick succeeds.
        when(userBff.deliverInApp(any()))
                .thenReturn(Mono.just(UserBffNotificationClient.Outcome.FAILED))
                .thenReturn(Mono.just(UserBffNotificationClient.Outcome.DELIVERED));
        String outboxId = seedRestriction("brandx", "subject-dave", null, "abuse");

        reconciler.runOnce().block(); // FAILED
        assertThat(countOf("notification_delivery")).isEqualTo(0);
        assertThat(deliveries.existsInApp(outboxId).block()).isFalse();
        // Cursor NOT advanced past the still-undelivered row.
        assertThat(countOf("notification_cursor")).isEqualTo(0);
        assertThat(metric("notification.reconcile.failed")).isEqualTo(1d);

        reconciler.runOnce().block(); // retried → DELIVERED
        assertThat(countOf("notification_delivery")).isEqualTo(1);
        assertThat(deliveries.statusInApp(outboxId).block())
                .isEqualTo(NotificationDeliveryRepository.STATUS_SENT);
        verify(userBff, times(2)).deliverInApp(any());
    }

    // ── NEVER-HARD-FAIL / poison: retries then dead-letters; never wedges ───
    @Test
    void poisonRow_isRetriedThenDeadLettered_andNeverBlocksAGoodRow() {
        // The poison row ALWAYS fails; a second (good) row always delivers.
        when(userBff.deliverInApp(any())).thenAnswer(inv -> {
            UserBffNotification n = inv.getArgument(0);
            return "subject-poison".equals(n.userSubject())
                    ? Mono.just(UserBffNotificationClient.Outcome.FAILED)
                    : Mono.just(UserBffNotificationClient.Outcome.DELIVERED);
        });
        String poison = seedRestriction("brandx", "subject-poison", null, "abuse");
        // Insert the good row a hair LATER so the poison is processed first (oldest-first).
        Mono.delay(java.time.Duration.ofMillis(5)).block();
        String good = seedRestriction("brandx", "subject-good", null, "abuse");

        // maxAttempts=3 → ticks 1,2 fail (no delivery), tick 3 dead-letters the poison.
        // Each tick the good row still delivers (idempotently — only once recorded).
        for (int i = 0; i < 3; i++) {
            // must never throw out of the tick.
            reconciler.runOnce().block();
        }

        // Poison dead-lettered as 'failed'.
        assertThat(deliveries.statusInApp(poison).block())
                .isEqualTo(NotificationDeliveryRepository.STATUS_FAILED);
        assertThat(metric("notification.reconcile.dead_lettered")).isEqualTo(1d);
        // The good row delivered exactly once (never blocked by the poison head-of-line).
        assertThat(deliveries.statusInApp(good).block())
                .isEqualTo(NotificationDeliveryRepository.STATUS_SENT);
        // Two delivery rows total (one failed, one sent).
        assertThat(countOf("notification_delivery")).isEqualTo(2);
    }

    // ── IN-APP ONLY: the only external call is the user-bff client ──────────
    @Test
    void inAppOnly_noDeliveryWhenNothingUndelivered_andClientIsTheSoleCollaborator() {
        // No outbox rows → no calls at all.
        when(userBff.deliverInApp(any()))
                .thenReturn(Mono.just(UserBffNotificationClient.Outcome.DELIVERED));

        reconciler.runOnce().block();

        verify(userBff, never()).deliverInApp(any());
        assertThat(countOf("notification_delivery")).isEqualTo(0);
        // (The reconciler holds NO Matrix/Akkoma/email collaborator — it is constructed
        //  with only the user-bff client; in-app is the single channel by construction.)
    }

    // ── SUPPRESSED: a recipient-silenced verdict records a 'skipped' delivery ─
    @Test
    void suppressedVerdict_recordsSkippedDelivery_andIsTerminal() {
        when(userBff.deliverInApp(any()))
                .thenReturn(Mono.just(UserBffNotificationClient.Outcome.SUPPRESSED));
        String outboxId = seedRestriction("brandx", "subject-erin", null, "abuse");

        reconciler.runOnce().block();
        reconciler.runOnce().block(); // re-tick: terminal, no second call

        assertThat(deliveries.statusInApp(outboxId).block())
                .isEqualTo(NotificationDeliveryRepository.STATUS_SKIPPED);
        verify(userBff, times(1)).deliverInApp(any());
        assertThat(metric("notification.reconcile.suppressed")).isEqualTo(1d);
    }

    // ── CURSOR ADVANCE: a delivered row advances the in-app cursor watermark ─
    @Test
    void deliveredRow_advancesInAppCursor() {
        when(userBff.deliverInApp(any()))
                .thenReturn(Mono.just(UserBffNotificationClient.Outcome.DELIVERED));
        String outboxId = seedRestriction("brandx", "subject-frank", null, "abuse");

        reconciler.runOnce().block();

        String wm = cursor.find(NotificationCursorRepository.CONSUMER_IN_APP).block();
        assertThat(wm).isEqualTo(outboxId);
    }
}
