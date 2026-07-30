package systems.hugmesh.adminbff.backingservices;

import io.r2dbc.spi.ConnectionFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.notification.NotificationOutbox;
import systems.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository;
import systems.hugmesh.adminbff.notification.NotificationOutboxRepository;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.adminbff.testutil.R2dbcRepos;
import systems.hugmesh.adminbff.web.dto.SetBackingServiceModeRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

/**
 * The backing-service mode-change transactional-outbox behaviour, proven over a REAL Postgres
 * (Testcontainers, {@link TestDatabaseConfig}) with the production Liquibase changelog applied
 * (the 062 outbox + 310 backing_service_mode tables) and a real {@link R2dbcTransactionManager}
 * over the SAME {@link ConnectionFactory} the {@link DatabaseClient} uses — so the mode-ledger
 * write + the notification_outbox write are genuinely in one connection's transaction. Mirrors
 * {@code BackupOutboxTransactionTest} EXACTLY for the {@code backing-service-mode-changed} event.
 *
 * <p><b>Harness:</b> requires Docker (Testcontainers, {@link TestDatabaseConfig}) and runs
 * anywhere one is available (CI or a Docker-enabled dev box), like the sibling
 * {@code cloudbackup} DB suites. See {@link BackingServiceControllerTest} for the
 * offline security-surface coverage.
 *
 * <ul>
 *   <li>HAPPY — a mode change writes the backing_service_mode ledger row AND exactly one
 *       {@code backing-service-mode-changed} outbox row, atomically.</li>
 *   <li>NO IDENTITY / SECRET LEAK — the outbox payload carries service-id/kind/tier/mode but
 *       NEVER the acting superadmin, the managed endpoint, or the creds reference.</li>
 *   <li>COUPLED ROLLBACK — an outbox-insert failure rolls the ledger write back (no orphan row).</li>
 *   <li>SHIPS DARK — no delivery rows; the outbox row is written but NOTHING consumes it.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
class BackingServiceOutboxTransactionTest {

    @Autowired DatabaseClient db;
    @Autowired ConnectionFactory connectionFactory;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM notification_delivery").fetch().rowsUpdated().block();
        db.sql("DELETE FROM notification_outbox").fetch().rowsUpdated().block();
        db.sql("DELETE FROM backing_service_mode").fetch().rowsUpdated().block();
    }

    private TransactionalOperator tx() {
        return TransactionalOperator.create(new R2dbcTransactionManager(connectionFactory));
    }

    private BackingServiceModeRepository modes() {
        return new BackingServiceModeRepository(R2dbcRepos.of(db, BackingServiceModeR2dbcRepository.class));
    }

    private NotificationOutboxRepository outbox() {
        return new NotificationOutboxRepository(R2dbcRepos.of(db, NotificationOutboxR2dbcRepository.class));
    }

    /** An ENABLED service (dark-gate off) so recordMode proceeds to the real writes. */
    private BackingServiceService service(BackingServiceModeRepository modes,
                                          NotificationOutboxRepository outbox) {
        return new BackingServiceService(true, modes, outbox, tx());
    }

    private long countOf(String table) {
        Long c = db.sql("SELECT count(*) AS c FROM " + table)
                .map((row, meta) -> row.get("c", Long.class)).first().block();
        return c == null ? 0 : c;
    }

    private static SetBackingServiceModeRequest managedReq(String endpoint, String credsRef) {
        return new SetBackingServiceModeRequest("managed", endpoint, credsRef);
    }

    // ── HAPPY: ledger row + exactly one mode-changed outbox row, atomic ──
    @Test
    void modeChange_writesLedgerAndExactlyOneOutboxRow() {
        NotificationOutboxRepository outbox = outbox();
        BackingServiceService svc = service(modes(), outbox);

        BackingServiceMode recorded = svc.recordMode("superadmin",
                "postgres-admin-bff", managedReq("db.rds.amazonaws.com:5432",
                        "hugmesh/postgres-admin-bff")).block();
        assertThat(recorded).isNotNull();
        assertThat(recorded.mode()).isEqualTo("managed");
        assertThat(recorded.generation()).isEqualTo(1L);

        assertThat(countOf("backing_service_mode")).isEqualTo(1);
        assertThat(countOf("notification_outbox")).isEqualTo(1);
        NotificationOutbox row = outbox.findBySource(
                NotificationOutbox.SOURCE_BACKING_SERVICE_MODE, recorded.id(),
                NotificationOutbox.CATEGORY_BACKING_SERVICE_MODE_CHANGED).block();
        assertThat(row).isNotNull();
        assertThat(row.sourceId()).isEqualTo(recorded.id());
        assertThat(row.category()).isEqualTo("backing-service-mode-changed");
        // Payload carries service-id/kind/tier/mode.
        String payload = row.payload();
        assertThat(payload).contains("\"service_id\":\"postgres-admin-bff\"");
        assertThat(payload).contains("\"kind\":\"postgres\"");
        assertThat(payload).contains("\"tier\":2");
        assertThat(payload).contains("\"mode\":\"managed\"");
    }

    // ── NO IDENTITY / SECRET LEAK: payload never contains actor / endpoint / creds ref ──
    @Test
    void modeChangeOutboxPayload_carriesNeutralFacts_butNeverActorEndpointOrCredsRef() {
        NotificationOutboxRepository outbox = outbox();
        BackingServiceService svc = service(modes(), outbox);

        String actor = "superadmin-SECRET-IDENTITY";
        String endpoint = "very-secret-host.rds.amazonaws.com:5432";
        String credsRef = "hugmesh/very-secret-creds-path";
        BackingServiceMode recorded = svc.recordMode(actor, "object-store",
                managedReq(endpoint, credsRef)).block();

        NotificationOutbox row = outbox.findBySource(
                NotificationOutbox.SOURCE_BACKING_SERVICE_MODE, recorded.id(),
                NotificationOutbox.CATEGORY_BACKING_SERVICE_MODE_CHANGED).block();
        assertThat(row).isNotNull();
        String payload = row.payload();
        assertThat(payload).doesNotContain(actor);
        assertThat(payload).doesNotContain("superadmin");
        assertThat(payload).doesNotContain(endpoint);
        assertThat(payload).doesNotContain(credsRef);
        assertThat(payload).doesNotContain("creds_ref");
        assertThat(payload).doesNotContain("endpoint");
    }

    // ── COUPLED ROLLBACK: an outbox-insert failure rolls the ledger write back ──
    @Test
    void outboxInsertFailure_rollsBackTheLedgerRow_noOrphan() {
        NotificationOutboxRepository outbox = spy(outbox());
        doReturn(Mono.error(new RuntimeException("outbox boom")))
                .when(outbox).insert(anyString(), anyString(), anyString(), anyString(), any());
        BackingServiceService svc = service(modes(), outbox);

        StepVerifier.create(svc.recordMode("superadmin", "kafka",
                        managedReq("b.msk:9094", null)))
                .expectErrorMessage("outbox boom")
                .verify();

        // BOTH legs rolled back: no ledger row, no outbox row.
        assertThat(countOf("backing_service_mode")).isEqualTo(0);
        assertThat(countOf("notification_outbox")).isEqualTo(0);
    }

    // ── SHIPS DARK: the outbox row exists, but NOTHING consumes it (no delivery rows) ──
    @Test
    void shipsDark_noDeliveryRows_outboxWrittenButUndelivered() {
        NotificationOutboxRepository outbox = outbox();
        BackingServiceService svc = service(modes(), outbox);

        svc.recordMode("superadmin", "smtp", managedReq("email-smtp.us-east-1.amazonaws.com:587", null)).block();

        assertThat(countOf("notification_outbox")).isEqualTo(1);
        assertThat(countOf("notification_delivery")).isEqualTo(0);
    }
}
