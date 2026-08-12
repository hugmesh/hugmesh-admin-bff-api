package net.hugmesh.adminbff.notification;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The feature/infra notification trigger over a REAL H2 with the 062 spine applied.
 *
 * <ul>
 *   <li>EMIT — writes a feature-availability / infra-impacting outbox row for the
 *       recipient, in the caller's domain, with a NEUTRAL payload (target + reason, no
 *       actor).</li>
 *   <li>IDEMPOTENT — a re-emit with the same eventKey is a no-op (returns false, no 2nd
 *       row).</li>
 *   <li>FAIL-CLOSED — a blank domain / recipient errors (never silently writes).</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@org.springframework.test.context.TestPropertySource(properties = "test.context.key=feature-notification-service")
class FeatureNotificationServiceTest {

    @Autowired DatabaseClient db;

    private NotificationOutboxRepository outbox;
    private FeatureNotificationService service;

    @BeforeEach
    void setup() {
        db.sql("DELETE FROM notification_outbox").fetch().rowsUpdated().block();
        outbox = new NotificationOutboxRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository.class));
        service = new FeatureNotificationService(outbox);
    }

    private long count() {
        Long c = db.sql("SELECT count(*) AS c FROM notification_outbox")
                .map((row, meta) -> row.get("c", Long.class)).first().block();
        return c == null ? 0 : c;
    }

    // ── EMIT writes a neutral feature-availability outbox row ────────────────
    @Test
    void emit_writesNeutralFeatureRow_inCallerDomain() {
        StepVerifier.create(service.emit(FeatureNotificationService.Kind.FEATURE_AVAILABILITY,
                        "brandx", "subject-alice", "feat-key-1", "the wiki is now available"))
                .assertNext(inserted -> assertThat(inserted).isTrue())
                .verifyComplete();

        NotificationOutbox row = outbox.findBySource(NotificationOutbox.SOURCE_PLATFORM_EVENT,
                "feat-key-1", NotificationOutbox.CATEGORY_FEATURE_AVAILABILITY).block();
        assertThat(row).isNotNull();
        assertThat(row.domain()).isEqualTo("brandx");
        // NEUTRAL payload: target + reason, NEVER an actor.
        assertThat(row.payload()).contains("subject-alice").contains("the wiki is now available");
        assertThat(row.payload()).doesNotContain("actor").doesNotContain("set_by");
    }

    // ── IDEMPOTENT: a re-emit with the same key inserts no second row ────────
    @Test
    void emit_sameEventKey_isIdempotent() {
        service.emit(FeatureNotificationService.Kind.INFRA_IMPACTING,
                "brandx", "subject-bob", "infra-key-1", "planned maintenance").block();
        StepVerifier.create(service.emit(FeatureNotificationService.Kind.INFRA_IMPACTING,
                        "brandx", "subject-bob", "infra-key-1", "planned maintenance"))
                .assertNext(inserted -> assertThat(inserted).isFalse())   // deduped
                .verifyComplete();
        assertThat(count()).isEqualTo(1);
    }

    // ── FAIL-CLOSED: a blank domain / recipient errors ──────────────────────
    @Test
    void emit_blankDomainOrRecipient_errors_andWritesNothing() {
        StepVerifier.create(service.emit(FeatureNotificationService.Kind.FEATURE_AVAILABILITY,
                        "  ", "subject-x", "k", "r"))
                .expectError(IllegalArgumentException.class).verify();
        StepVerifier.create(service.emit(FeatureNotificationService.Kind.FEATURE_AVAILABILITY,
                        "brandx", "  ", "k", "r"))
                .expectError(IllegalArgumentException.class).verify();
        assertThat(count()).isEqualTo(0);
    }
}
