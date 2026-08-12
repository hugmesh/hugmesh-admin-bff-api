package net.hugmesh.adminbff.notification;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.lease.AlwaysLeader;
import net.hugmesh.adminbff.notification.channel.ChannelMessage;
import net.hugmesh.adminbff.notification.channel.ChannelOutcome;
import net.hugmesh.adminbff.notification.channel.NotificationChannel;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The EXTERNAL-CHANNEL fan-out reconciler over a REAL H2 (PG-compat) with the production
 * 062 notification spine applied, using a controllable fake {@link NotificationChannel}.
 *
 * <ul>
 *   <li>HAPPY — an enabled+available channel delivers an outbox row once and records a
 *       per-channel {@code sent} delivery (channel != 'in-app') + advances the channel's
 *       OWN cursor ('ext:<channel>').</li>
 *   <li>NEUTRAL — the message handed to the adapter is impersonal (no actor).</li>
 *   <li>CHANNEL-ABSENT-DEGRADE — a DISABLED channel does no work; an UNAVAILABLE channel
 *       skips the row (records nothing, does NOT advance) and retries when it recovers.</li>
 *   <li>PER-DOMAIN ISOLATION — a channel available for domain A but not B delivers ONLY
 *       the domain-A row; the domain-B row stays undelivered for that channel.</li>
 *   <li>IDEMPOTENT — a re-tick over a delivered row sends nothing more.</li>
 *   <li>POISON — a row that always FAILS dead-letters after N attempts; never wedges.</li>
 *   <li>NO-MOD-IDENTITY — the neutral body never carries an actor field.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@org.springframework.test.context.TestPropertySource(properties = "test.context.key=external-channel-reconciler")
class ExternalChannelReconcilerTest {

    @Autowired DatabaseClient db;

    private NotificationDeliveryRepository deliveries;
    private NotificationCursorRepository cursor;
    private NotificationOutboxRepository outbox;
    private MeterRegistry meters;

    /** A controllable channel: enabled flag, per-domain availability set, fixed outcome,
     *  and a record of every (recipient, message) it was asked to send. */
    static class FakeChannel implements NotificationChannel {
        final String name;
        boolean enabled = true;
        Set<String> availableDomains = Set.of();   // empty = available nowhere
        ChannelOutcome outcome = ChannelOutcome.SENT;
        final List<ChannelMessage> sent = new CopyOnWriteArrayList<>();
        final List<String> recipients = new CopyOnWriteArrayList<>();
        FakeChannel(String name) { this.name = name; }
        @Override public String name() { return name; }
        @Override public boolean enabled() { return enabled; }
        @Override public Mono<Boolean> available(String domain) {
            return Mono.just(availableDomains.contains(domain));
        }
        @Override public Mono<ChannelOutcome> send(String domain, String recipient, ChannelMessage m) {
            recipients.add(recipient);
            sent.add(m);
            return Mono.just(outcome);
        }
    }

    @BeforeEach
    void setup() {
        db.sql("DELETE FROM notification_delivery").fetch().rowsUpdated().block();
        db.sql("DELETE FROM notification_cursor").fetch().rowsUpdated().block();
        db.sql("DELETE FROM notification_outbox").fetch().rowsUpdated().block();
        deliveries = new NotificationDeliveryRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationDeliveryR2dbcRepository.class));
        cursor = new NotificationCursorRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationCursorR2dbcRepository.class));
        outbox = new NotificationOutboxRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository.class));
        meters = new SimpleMeterRegistry();
    }

    private ExternalChannelReconciler reconciler(NotificationChannel... ch) {
        return new ExternalChannelReconciler(deliveries, cursor, List.of(ch),
                new AlwaysLeader(), meters, 100, 3);
    }

    private String seed(String domain, String userSubject) {
        String sourceId = UUID.randomUUID().toString();
        String payload = AccountRestrictionPayload.build(userSubject, "PROFILE", 3600L, "abuse");
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

    // ── HAPPY: per-channel sent delivery + own cursor ────────────────────────
    @Test
    void enabledAvailableChannel_deliversOnce_recordsPerChannelSent_advancesOwnCursor() {
        FakeChannel matrix = new FakeChannel("matrix");
        matrix.availableDomains = Set.of("brandx");
        String outboxId = seed("brandx", "subject-alice");

        reconciler(matrix).runOnce().block();

        assertThat(matrix.sent).hasSize(1);
        assertThat(deliveries.status(outboxId, "matrix").block())
                .isEqualTo(NotificationDeliveryRepository.STATUS_SENT);
        // The channel's OWN cursor advanced; the in-app cursor is untouched.
        assertThat(cursor.find("ext:matrix").block()).isEqualTo(outboxId);
        assertThat(cursor.find(NotificationCursorRepository.CONSUMER_IN_APP).block()).isNull();
    }

    // ── NEUTRAL / NO-MOD-IDENTITY: the message carries no actor ──────────────
    @Test
    void deliveredMessage_isNeutral_neverCarriesAnActor() {
        FakeChannel matrix = new FakeChannel("matrix");
        matrix.availableDomains = Set.of("brandx");
        seed("brandx", "subject-bob");

        reconciler(matrix).runOnce().block();

        ChannelMessage m = matrix.sent.get(0);
        assertThat(m.title()).isEqualTo("Your account access changed");
        assertThat(m.body()).doesNotContain("mod").doesNotContain("actor").doesNotContain("set_by");
        assertThat(m.body()).contains("temporary");   // ttl surfaced, identity not
    }

    // ── DISABLED channel does no work ────────────────────────────────────────
    @Test
    void disabledChannel_doesNoWork() {
        FakeChannel matrix = new FakeChannel("matrix");
        matrix.enabled = false;
        matrix.availableDomains = Set.of("brandx");
        seed("brandx", "subject-carol");

        reconciler(matrix).runOnce().block();

        assertThat(matrix.sent).isEmpty();
        assertThat(countOf("notification_delivery")).isEqualTo(0);
    }

    // ── UNAVAILABLE channel skips the row, no advance, retries on recover ────
    @Test
    void unavailableChannel_skipsRow_doesNotAdvance_retriesWhenAvailable() {
        FakeChannel matrix = new FakeChannel("matrix");
        matrix.availableDomains = Set.of();   // unavailable everywhere
        String outboxId = seed("brandx", "subject-dave");
        ExternalChannelReconciler r = reconciler(matrix);

        r.runOnce().block();   // unavailable → skipped, nothing recorded
        assertThat(matrix.sent).isEmpty();
        assertThat(countOf("notification_delivery")).isEqualTo(0);
        assertThat(cursor.find("ext:matrix").block()).isNull();   // cursor NOT advanced

        matrix.availableDomains = Set.of("brandx");   // channel recovers
        r.runOnce().block();
        assertThat(matrix.sent).hasSize(1);
        assertThat(deliveries.status(outboxId, "matrix").block())
                .isEqualTo(NotificationDeliveryRepository.STATUS_SENT);
    }

    // ── PER-DOMAIN ISOLATION: available for A, not B ─────────────────────────
    @Test
    void perDomainIsolation_deliversOnlyTheAvailableDomainsRow() {
        FakeChannel matrix = new FakeChannel("matrix");
        matrix.availableDomains = Set.of("brand-a");   // available for A only
        String aId = seed("brand-a", "subject-a");
        String bId = seed("brand-b", "subject-b");

        reconciler(matrix).runOnce().block();

        // Only the brand-a row delivered; brand-b stays undelivered for this channel.
        assertThat(matrix.sent).hasSize(1);
        assertThat(deliveries.status(aId, "matrix").block())
                .isEqualTo(NotificationDeliveryRepository.STATUS_SENT);
        assertThat(deliveries.status(bId, "matrix").block()).isNull();
    }

    // ── IDEMPOTENT: re-tick over a delivered row sends nothing more ──────────
    @Test
    void reTickOverDeliveredRow_sendsNothingMore() {
        FakeChannel matrix = new FakeChannel("matrix");
        matrix.availableDomains = Set.of("brandx");
        seed("brandx", "subject-erin");
        ExternalChannelReconciler r = reconciler(matrix);

        r.runOnce().block();
        r.runOnce().block();

        assertThat(matrix.sent).hasSize(1);
        assertThat(countOf("notification_delivery")).isEqualTo(1);
    }

    // ── POISON: an always-FAILED row dead-letters after N, never wedges ──────
    @Test
    void poisonRow_deadLettersAfterMaxAttempts() {
        FakeChannel matrix = new FakeChannel("matrix");
        matrix.availableDomains = Set.of("brandx");
        matrix.outcome = ChannelOutcome.FAILED;
        String outboxId = seed("brandx", "subject-poison");
        ExternalChannelReconciler r = reconciler(matrix);

        // maxAttempts=3 → ticks 1,2 fail (no delivery), tick 3 dead-letters as 'failed'.
        r.runOnce().block();
        assertThat(countOf("notification_delivery")).isEqualTo(0);
        r.runOnce().block();
        r.runOnce().block();

        assertThat(deliveries.status(outboxId, "matrix").block())
                .isEqualTo(NotificationDeliveryRepository.STATUS_FAILED);
    }

    // ── TWO CHANNELS: each independent (own delivery row + own cursor) ───────
    @Test
    void twoChannels_eachDeliverIndependently() {
        FakeChannel matrix = new FakeChannel("matrix");
        FakeChannel email = new FakeChannel("email");
        matrix.availableDomains = Set.of("brandx");
        email.availableDomains = Set.of("brandx");
        String outboxId = seed("brandx", "subject-frank");

        reconciler(matrix, email).runOnce().block();

        assertThat(deliveries.status(outboxId, "matrix").block())
                .isEqualTo(NotificationDeliveryRepository.STATUS_SENT);
        assertThat(deliveries.status(outboxId, "email").block())
                .isEqualTo(NotificationDeliveryRepository.STATUS_SENT);
        // two delivery rows, one per channel.
        assertThat(countOf("notification_delivery")).isEqualTo(2);
        assertThat(cursor.find("ext:matrix").block()).isEqualTo(outboxId);
        assertThat(cursor.find("ext:email").block()).isEqualTo(outboxId);
    }
}
