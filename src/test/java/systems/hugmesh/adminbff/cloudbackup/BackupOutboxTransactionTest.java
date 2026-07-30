package systems.hugmesh.adminbff.cloudbackup;

import io.r2dbc.spi.ConnectionFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.notification.NotificationOutbox;
import systems.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository;
import systems.hugmesh.adminbff.notification.NotificationOutboxRepository;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.adminbff.testutil.R2dbcRepos;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The backup/restore notification transactional-outbox behaviour, proven over a REAL
 * Postgres (Testcontainers) with the production Liquibase changelog applied (the 062
 * outbox + 160 cloud-backup tables) and a real {@link R2dbcTransactionManager} over the
 * SAME {@link ConnectionFactory} the {@link DatabaseClient} uses — so the backup_set
 * effect write + the notification_outbox write are genuinely in one connection's
 * transaction. This mirrors {@code SuspensionOutboxTransactionTest} EXACTLY for the
 * backup-started / restore-started events (closing the BackupService TODOs).
 *
 * <p>Delineated:
 * <ul>
 *   <li>HAPPY — a backup writes the backup_set effect AND exactly one
 *       {@code backup-started} outbox row, atomically, domain stamped from the effect.</li>
 *   <li>NO IDENTITY LEAK — the outbox payload carries scope/version/service-count but
 *       NEVER the acting admin ({@code createdBy}) nor any destination ref / key.</li>
 *   <li>COUPLED ROLLBACK — an outbox-insert failure rolls the backup_set effect back (no
 *       orphan set), proving the two writes are one transaction.</li>
 *   <li>EFFECT FAILURE — when the backup_set write fails, NO outbox row is left behind.</li>
 *   <li>RESTORE — a restore writes a {@code restore-started} row in the restore tx; an
 *       outbox failure rolls the (dark) restore effect back.</li>
 *   <li>SHIPS DARK — no delivery rows; the outbox row is written but NOTHING consumes it.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
class BackupOutboxTransactionTest {

    @Autowired DatabaseClient db;
    @Autowired ConnectionFactory connectionFactory;

    private static final PrincipalDomain SCOPE = scope("brandx");

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM notification_delivery").fetch().rowsUpdated().block();
        db.sql("DELETE FROM notification_outbox").fetch().rowsUpdated().block();
        db.sql("DELETE FROM backup_artifact").fetch().rowsUpdated().block();
        db.sql("DELETE FROM backup_set").fetch().rowsUpdated().block();
    }

    private TransactionalOperator tx() {
        return TransactionalOperator.create(new R2dbcTransactionManager(connectionFactory));
    }

    private BackupSetRepository sets() {
        return new BackupSetRepository(R2dbcRepos.of(db, BackupSetR2dbcRepository.class));
    }

    private BackupArtifactRepository artifacts() {
        return new BackupArtifactRepository(R2dbcRepos.of(db, BackupArtifactR2dbcRepository.class));
    }

    private NotificationOutboxRepository outbox() {
        return new NotificationOutboxRepository(R2dbcRepos.of(db, NotificationOutboxR2dbcRepository.class));
    }

    /** A dark (mocked) effector + a stub destination repo + an unused running-service
     *  provider — the real surfaces under test are the backup_set + outbox writes. */
    private BackupService service(BackupSetRepository sets, BackupArtifactRepository artifacts,
                                  NotificationOutboxRepository outbox) {
        BackupEffector effector = mock(BackupEffector.class);
        when(effector.startBackup(any())).thenReturn(Mono.empty());
        when(effector.startRestore(any())).thenReturn(Mono.empty());
        BackupDestinationRepository destinations = mock(BackupDestinationRepository.class);
        RunningServiceProvider running = mock(RunningServiceProvider.class);
        return new BackupService(sets, artifacts, destinations, running, effector, outbox, tx());
    }

    private long countOf(String table) {
        Long c = db.sql("SELECT count(*) AS c FROM " + table)
                .map((row, meta) -> row.get("c", Long.class)).first().block();
        return c == null ? 0 : c;
    }

    // ── HAPPY: effect + exactly one backup-started row, atomic, domain stamped ──
    @Test
    void backup_writesSetAndExactlyOneOutboxRow_domainStampedFromEffect() {
        NotificationOutboxRepository outbox = outbox();
        BackupService svc = service(sets(), artifacts(), outbox);

        BackupSet set = svc.create("k", BackupCloudScope.DOMAIN, List.of("postgres", "matrix"),
                BackupDestinationKind.OBJECT_STORE, "s3://b", null, "admin-alice", SCOPE).block();
        assertThat(set).isNotNull();

        assertThat(countOf("notification_outbox")).isEqualTo(1);
        assertThat(countOf("backup_set")).isEqualTo(1);
        NotificationOutbox row = outbox.findBySource(
                NotificationOutbox.SOURCE_BACKUP_SET, set.id(),
                NotificationOutbox.CATEGORY_BACKUP_STARTED).block();
        assertThat(row).isNotNull();
        // Domain stamped from the EFFECT's domain (which came from the acting scope).
        assertThat(row.domain()).isEqualTo("brandx");
        assertThat(row.domain()).isEqualTo(set.domain());
        assertThat(row.sourceId()).isEqualTo(set.id());
        assertThat(row.category()).isEqualTo("backup-started");
        // Payload carries the run context (scope/version/service-count/destination-kind).
        String payload = row.payload();
        assertThat(payload).contains("\"scope\":\"" + BackupCloudScope.DOMAIN.wire() + "\"");
        assertThat(payload).contains("\"version\":1");
        assertThat(payload).contains("\"service_count\":2");
        assertThat(payload).contains("object_store");
    }

    // ── NO IDENTITY LEAK: payload never contains the actor (createdBy) nor the dest ref ──
    @Test
    void backupOutboxPayload_carriesScopeVersionCount_butNeverActorNorDestinationRef() {
        NotificationOutboxRepository outbox = outbox();
        BackupService svc = service(sets(), artifacts(), outbox);

        String actor = "admin-alice-SECRET-IDENTITY";
        String destRef = "s3://very-secret-bucket-name";
        BackupSet set = svc.create("k", BackupCloudScope.DOMAIN, List.of("postgres"),
                BackupDestinationKind.OBJECT_STORE, destRef, "{\"repo\":\"secret-repo\"}",
                actor, SCOPE).block();

        NotificationOutbox row = outbox.findBySource(
                NotificationOutbox.SOURCE_BACKUP_SET, set.id(),
                NotificationOutbox.CATEGORY_BACKUP_STARTED).block();
        assertThat(row).isNotNull();
        String payload = row.payload();
        assertThat(payload).isNotNull();
        // ...but NEVER the acting admin identity, the destination ref, or the encryption meta.
        assertThat(payload).doesNotContain(actor);
        assertThat(payload).doesNotContain("admin-alice");
        assertThat(payload).doesNotContain("createdBy");
        assertThat(payload).doesNotContain("created_by");
        assertThat(payload).doesNotContain("actor");
        assertThat(payload).doesNotContain(destRef);
        assertThat(payload).doesNotContain("secret-repo");
        assertThat(payload).doesNotContain("destination_ref");
    }

    // ── COUPLED ROLLBACK: an outbox-insert failure rolls the backup_set effect back ──
    @Test
    void outboxInsertFailure_rollsBackTheBackupSet_noOrphanSet() {
        NotificationOutboxRepository outbox = spy(outbox());
        doReturn(Mono.error(new RuntimeException("outbox boom")))
                .when(outbox).insert(anyString(), anyString(), anyString(), anyString(), any());
        BackupService svc = service(sets(), artifacts(), outbox);

        StepVerifier.create(svc.create("k", BackupCloudScope.DOMAIN, List.of("postgres"),
                        BackupDestinationKind.OBJECT_STORE, "s3://b", null, "admin", SCOPE))
                .expectErrorMessage("outbox boom")
                .verify();

        // BOTH legs rolled back: no backup_set, no artifact, no outbox row.
        assertThat(countOf("backup_set")).isEqualTo(0);
        assertThat(countOf("backup_artifact")).isEqualTo(0);
        assertThat(countOf("notification_outbox")).isEqualTo(0);
    }

    // ── EFFECT FAILURE: a failed backup_set write leaves NO outbox row ──
    @Test
    void setWriteFailure_leavesNoOutboxRow() {
        BackupSetRepository sets = spy(sets());
        doReturn(Mono.error(new RuntimeException("set boom")))
                .when(sets).insert(anyString(), org.mockito.ArgumentMatchers.anyLong(), any(),
                        anyString(), anyString(), any(), any(), anyString(), any());
        NotificationOutboxRepository outbox = spy(outbox());
        BackupService svc = service(sets, artifacts(), outbox);

        StepVerifier.create(svc.create("k", BackupCloudScope.DOMAIN, List.of("postgres"),
                        BackupDestinationKind.OBJECT_STORE, "s3://b", null, "admin", SCOPE))
                .expectErrorMessage("set boom")
                .verify();

        assertThat(countOf("notification_outbox")).isEqualTo(0);
        assertThat(countOf("backup_set")).isEqualTo(0);
        // The outbox insert was never even attempted (effect failed first).
        verify(outbox, never()).insert(anyString(), anyString(), anyString(), anyString(), any());
    }

    // ── RESTORE: writes a restore-started row in the restore tx ──
    @Test
    void restore_writesExactlyOneRestoreStartedOutboxRow_inScope() {
        NotificationOutboxRepository outbox = outbox();
        BackupSetRepository sets = sets();
        BackupService svc = service(sets, artifacts(), outbox);

        // Seed a set the scoped admin owns, then restore it.
        BackupSet created = svc.create("k", BackupCloudScope.DOMAIN, List.of("postgres"),
                BackupDestinationKind.OBJECT_STORE, "s3://b", null, "admin", SCOPE).block();
        db.sql("DELETE FROM notification_outbox").fetch().rowsUpdated().block(); // drop the backup-started row

        BackupSet restored = svc.restore(created.id(), "admin-bob", SCOPE).block();
        assertThat(restored).isNotNull();

        assertThat(countOf("notification_outbox")).isEqualTo(1);
        NotificationOutbox row = outbox.findBySource(
                NotificationOutbox.SOURCE_BACKUP_SET, created.id(),
                NotificationOutbox.CATEGORY_RESTORE_STARTED).block();
        assertThat(row).isNotNull();
        assertThat(row.domain()).isEqualTo("brandx");
        assertThat(row.category()).isEqualTo("restore-started");
        // No actor, no destination kind on a restore (no fresh destination chosen).
        assertThat(row.payload()).doesNotContain("admin-bob");
        assertThat(row.payload()).doesNotContain("destination_kind");
    }

    // ── RESTORE COUPLED ROLLBACK: an outbox failure rolls the (dark) restore effect back ──
    @Test
    void restoreOutboxFailure_rollsBack_noRestoreStartedRow() {
        BackupSetRepository sets = sets();
        BackupService seedSvc = service(sets, artifacts(), outbox());
        BackupSet created = seedSvc.create("k", BackupCloudScope.DOMAIN, List.of("postgres"),
                BackupDestinationKind.OBJECT_STORE, "s3://b", null, "admin", SCOPE).block();
        db.sql("DELETE FROM notification_outbox").fetch().rowsUpdated().block();

        NotificationOutboxRepository outbox = spy(outbox());
        doReturn(Mono.error(new RuntimeException("restore outbox boom")))
                .when(outbox).insert(anyString(), anyString(), anyString(), anyString(), any());
        BackupService svc = service(sets, artifacts(), outbox);

        StepVerifier.create(svc.restore(created.id(), "admin-bob", SCOPE))
                .expectErrorMessage("restore outbox boom")
                .verify();

        assertThat(countOf("notification_outbox")).isEqualTo(0);
    }

    // ── SHIPS DARK: the outbox row exists, but NOTHING consumes it (no delivery rows) ──
    @Test
    void shipsDark_noDeliveryRows_outboxWrittenButUndelivered() {
        NotificationOutboxRepository outbox = outbox();
        BackupService svc = service(sets(), artifacts(), outbox);

        svc.create("k", BackupCloudScope.DOMAIN, List.of("postgres"),
                BackupDestinationKind.OBJECT_STORE, "s3://b", null, "admin", SCOPE).block();

        assertThat(countOf("notification_outbox")).isEqualTo(1);
        assertThat(countOf("notification_delivery")).isEqualTo(0);
        assertThat(countOf("notification_cursor")).isEqualTo(0);
    }

    /** Build a real scoped (non-superadmin) {@link PrincipalDomain} for {@code domain} from
     *  a validated-issuer JWT — the same mechanism the production controller uses, so the
     *  domain stamped on writes is genuinely scope-derived (never user-settable). */
    private static PrincipalDomain scope(String domain) {
        String issuer = "https://idp." + domain + ".example";
        DomainRegistry registry = new DomainRegistry("", issuer + "=" + domain);
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(issuer).claim("roles", List.of("admin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, registry);
    }
}
