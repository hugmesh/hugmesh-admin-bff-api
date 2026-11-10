package net.hugmesh.adminbff.notification.channel;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.lease.AlwaysLeader;
import net.hugmesh.adminbff.notification.AccountRestrictionPayload;
import net.hugmesh.adminbff.notification.ExternalChannelReconciler;
import net.hugmesh.adminbff.notification.NotificationCursorR2dbcRepository;
import net.hugmesh.adminbff.notification.NotificationCursorRepository;
import net.hugmesh.adminbff.notification.NotificationDeliveryR2dbcRepository;
import net.hugmesh.adminbff.notification.NotificationDeliveryRepository;
import net.hugmesh.adminbff.notification.NotificationOutbox;
import net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository;
import net.hugmesh.adminbff.notification.NotificationOutboxRepository;
import net.hugmesh.adminbff.notification.SystemChannelTokens;
import net.hugmesh.adminbff.notification.UserBffNotificationClient;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Matrix channel's FAILED -> retry -> dead-letter path driven by a REAL non-2xx reply
 * from a real HTTP server ({@link FakeMatrixHomeserver}), end to end through the real
 * {@link ExternalChannelReconciler} over H2 with the production notification spine — not a
 * channel mock that is told to answer FAILED.
 *
 * <ul>
 *   <li>A 500 on the send PUT is retried on every tick and dead-lettered as {@code failed}
 *       after {@code max-attempts}; no event is posted and no second DM room is created.</li>
 *   <li>A homeserver that recovers before the limit delivers the row once, as {@code sent}.</li>
 *   <li>The un-wired admin-seam path ({@code notify.matrix.dm.wired=false}) never makes a
 *       request and never reports {@code sent}: it dead-letters as {@code failed}.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@TestPropertySource(properties = "test.context.key=matrix-channel-dead-letter")
class MatrixChannelDeadLetterTest {

    private static final int MAX_ATTEMPTS = 3;

    @Autowired DatabaseClient db;

    private NotificationDeliveryRepository deliveries;
    private NotificationCursorRepository cursor;
    private NotificationOutboxRepository outbox;
    private FakeMatrixHomeserver hs;

    @BeforeEach
    void setup() throws Exception {
        db.sql("DELETE FROM notification_delivery").fetch().rowsUpdated().block();
        db.sql("DELETE FROM notification_cursor").fetch().rowsUpdated().block();
        db.sql("DELETE FROM notification_outbox").fetch().rowsUpdated().block();
        deliveries = new NotificationDeliveryRepository(R2dbcRepos.of(db, NotificationDeliveryR2dbcRepository.class));
        cursor = new NotificationCursorRepository(R2dbcRepos.of(db, NotificationCursorR2dbcRepository.class));
        outbox = new NotificationOutboxRepository(R2dbcRepos.of(db, NotificationOutboxR2dbcRepository.class));
        hs = new FakeMatrixHomeserver();
    }

    @AfterEach
    void down() {
        hs.close();
    }

    private MatrixChannel wiredChannel() {
        MatrixSystemDmClient dm = new MatrixSystemDmClient(WebClient.builder().baseUrl(hs.baseUrl()).build(),
                new SystemChannelTokens(FakeMatrixHomeserver.SYSTEM_TOKEN, "", "", ""), Duration.ofSeconds(5));
        // homeserver.admin.enabled=false: the wired client-API transport does not need the admin seam.
        WebClient unused = WebClient.builder().baseUrl(hs.baseUrl()).build();
        return new MatrixChannel(new HomeserverAdminClient(unused, unused, false), true, true, dm);
    }

    private ExternalChannelReconciler reconciler(NotificationChannel ch) {
        return new ExternalChannelReconciler(deliveries, cursor, List.of(ch),
                new AlwaysLeader(), new SimpleMeterRegistry(),
                // user-bff gate off: no preference lookup, every category reads as enabled.
                new UserBffNotificationClient(null, false, null), 100, MAX_ATTEMPTS);
    }

    private String seed(String userSubject) {
        String sourceId = UUID.randomUUID().toString();
        String payload = AccountRestrictionPayload.build(userSubject, "PROFILE", 3600L, "abuse");
        outbox.insert("brandx", NotificationOutbox.SOURCE_ACCESS_SUSPENSION, sourceId,
                NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION, payload).block();
        return outbox.findBySource(NotificationOutbox.SOURCE_ACCESS_SUSPENSION, sourceId,
                NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION).block().id();
    }

    private String status(String outboxId) {
        return deliveries.status(outboxId, MatrixChannel.NAME).block();
    }

    @Test
    void sendServerError_isRetriedEachTick_thenDeadLetteredAsFailed_neverSent() {
        String id = seed("hugmesh/alice");
        hs.forcedStatus.put("PUT /send/m.room.message/hm-" + id, 500);
        ExternalChannelReconciler r = reconciler(wiredChannel());

        for (int tick = 1; tick < MAX_ATTEMPTS; tick++) {
            r.runOnce().block();
            assertThat(status(id)).as("after failed tick %d", tick).isNull();
            assertThat(hs.count("PUT", "/send/m.room.message/")).isEqualTo(tick);
        }
        r.runOnce().block();

        assertThat(status(id)).isEqualTo(NotificationDeliveryRepository.STATUS_FAILED);
        assertThat(hs.count("PUT", "/send/m.room.message/")).isEqualTo(MAX_ATTEMPTS);
        assertThat(hs.events).isEmpty();
        // a 5xx is not "the room is gone": one DM room for all the retries
        assertThat(hs.count("POST", "createRoom")).isEqualTo(1);

        // dead-lettered rows are terminal: a further tick sends nothing more
        r.runOnce().block();
        assertThat(hs.count("PUT", "/send/m.room.message/")).isEqualTo(MAX_ATTEMPTS);
        assertThat(cursor.find("ext:" + MatrixChannel.NAME).block()).isEqualTo(id);
    }

    @Test
    void sendServerError_thenRecovery_deliversOnce_asSent() {
        String id = seed("hugmesh/alice");
        hs.forcedStatus.put("PUT /send/m.room.message/hm-" + id, 500);
        ExternalChannelReconciler r = reconciler(wiredChannel());

        r.runOnce().block();
        assertThat(status(id)).isNull();
        assertThat(hs.events).isEmpty();

        hs.forcedStatus.clear();
        r.runOnce().block();

        assertThat(status(id)).isEqualTo(NotificationDeliveryRepository.STATUS_SENT);
        assertThat(hs.events).hasSize(1);
        assertThat(hs.events.get(0).txn()).isEqualTo("hm-" + id);
        assertThat(hs.events.get(0).msgtype()).isEqualTo("m.text");
    }

    @Test
    void unwiredAdminSeam_makesNoRequest_andDeadLettersAsFailed_neverSent() {
        String id = seed("hugmesh/alice");
        // notify.matrix.dm.wired=false, homeserver.admin.enabled=true: the admin-seam DM is a stub
        WebClient toFake = WebClient.builder().baseUrl(hs.baseUrl()).build();
        MatrixChannel ch = new MatrixChannel(new HomeserverAdminClient(toFake, toFake, true), true, true);
        assertThat(ch.available("brandx").block()).isTrue();
        ExternalChannelReconciler r = reconciler(ch);

        for (int tick = 0; tick < MAX_ATTEMPTS; tick++) {
            r.runOnce().block();
        }

        assertThat(status(id)).isEqualTo(NotificationDeliveryRepository.STATUS_FAILED);
        assertThat(hs.requests).isEmpty();
        assertThat(hs.events).isEmpty();
    }
}
