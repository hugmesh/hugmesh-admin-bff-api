package net.hugmesh.adminbff.notification;

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
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.suspension.AccessSuspension;
import net.hugmesh.adminbff.suspension.AccessSuspensionRepository;
import net.hugmesh.adminbff.suspension.AccessSyncActions;
import net.hugmesh.adminbff.suspension.SuspensionService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The Notifications PR2 transactional-outbox spine, proven over a REAL H2 (PG-compat)
 * with the production Liquibase changelog applied (the 062 tables) and a real
 * {@link R2dbcTransactionManager} over the SAME {@link ConnectionFactory} the
 * {@link DatabaseClient} uses — so the effect write + the outbox write are genuinely in
 * one connection's transaction.
 *
 * <p>Delineated:
 * <ul>
 *   <li>HAPPY — a ban writes the access_suspension effect AND exactly one
 *       notification_outbox row, atomically, domain stamped from the effect.</li>
 *   <li>NO IDENTITY LEAK — the outbox payload carries reason/ttl/target but NEVER the
 *       acting mod/admin ({@code set_by}).</li>
 *   <li>COUPLED ROLLBACK — an outbox-insert failure rolls the effect back (no orphan
 *       suspension), proving the two writes are one transaction.</li>
 *   <li>EFFECT FAILURE — when the effect write fails, NO outbox row is left behind.</li>
 *   <li>DEDUP — an idempotent re-ban of an already-active target writes NO new effect
 *       and NO second outbox row (UNIQUE(source_table, source_id, category)).</li>
 *   <li>SHIPS DARK — no delivery/cursor side-effects and no external delivery call: the
 *       reconcile tick is the ONLY downstream interaction and it is best-effort.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
class SuspensionOutboxTransactionTest {

    @Autowired DatabaseClient db;
    @Autowired ConnectionFactory connectionFactory;

    private static final PrincipalDomain SCOPE = scope("brandx");

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM notification_delivery").fetch().rowsUpdated().block();
        db.sql("DELETE FROM notification_outbox").fetch().rowsUpdated().block();
        db.sql("DELETE FROM access_suspension").fetch().rowsUpdated().block();
    }

    private TransactionalOperator tx() {
        return TransactionalOperator.create(new R2dbcTransactionManager(connectionFactory));
    }

    private AccessSyncActions ticking() {
        AccessSyncActions actions = mock(AccessSyncActions.class);
        when(actions.triggerTick()).thenReturn(Mono.empty());
        return actions;
    }

    private SuspensionService service(NotificationOutboxRepository outbox, AccessSyncActions actions) {
        return new SuspensionService(new AccessSuspensionRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.suspension.AccessSuspensionRowRepository.class)), actions, outbox, tx());
    }

    private long outboxCount() {
        return countOf("notification_outbox");
    }

    private long suspensionCount() {
        return countOf("access_suspension");
    }

    private long countOf(String table) {
        Long c = db.sql("SELECT count(*) AS c FROM " + table)
                .map((row, meta) -> row.get("c", Long.class)).first().block();
        return c == null ? 0 : c;
    }

    // ── HAPPY: effect + exactly one outbox row, atomic, domain stamped ──────
    @Test
    void ban_writesEffectAndExactlyOneOutboxRow_domainStampedFromEffect() {
        NotificationOutboxRepository outbox = new NotificationOutboxRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository.class));
        SuspensionService svc = service(outbox, ticking());

        AccessSuspension s = svc.suspend(AccessSuspension.ROLE_PROFILE, "alice",
                3600L, "abuse", "mod-mallory", SCOPE).block();
        assertThat(s).isNotNull();

        assertThat(outboxCount()).isEqualTo(1);
        NotificationOutbox row = outbox.findBySource(
                NotificationOutbox.SOURCE_ACCESS_SUSPENSION, s.id(),
                NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION).block();
        assertThat(row).isNotNull();
        // Domain stamped from the EFFECT's domain (which came from the acting scope).
        assertThat(row.domain()).isEqualTo("brandx");
        assertThat(row.domain()).isEqualTo(s.domain());
        assertThat(row.sourceId()).isEqualTo(s.id());
        assertThat(row.category()).isEqualTo("account-restriction");
    }

    // ── NO IDENTITY LEAK: payload never contains the actor (set_by) ─────────
    @Test
    void outboxPayload_carriesReasonTtlTarget_butNeverTheActorIdentity() {
        NotificationOutboxRepository outbox = new NotificationOutboxRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository.class));
        SuspensionService svc = service(outbox, ticking());

        // A very identifiable actor handle — assert it NEVER appears in the payload.
        String actor = "mod-mallory-SECRET-IDENTITY";
        AccessSuspension s = svc.suspend(AccessSuspension.ROLE_PROFILE, "victim-bob",
                7200L, "ban-reason-spam", actor, SCOPE).block();

        NotificationOutbox row = outbox.findBySource(
                NotificationOutbox.SOURCE_ACCESS_SUSPENSION, s.id(),
                NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION).block();
        assertThat(row).isNotNull();
        String payload = row.payload();
        assertThat(payload).isNotNull();
        // Carries the target + reason + ttl context...
        assertThat(payload).contains("victim-bob");
        assertThat(payload).contains("ban-reason-spam");
        assertThat(payload).contains("7200");
        // ...but NEVER the acting moderator identity, by any spelling.
        assertThat(payload).doesNotContain(actor);
        assertThat(payload).doesNotContain("mod-mallory");
        assertThat(payload).doesNotContain("set_by");
        assertThat(payload).doesNotContain("actor");
    }

    // ── COUPLED ROLLBACK: an outbox-insert failure rolls the EFFECT back ────
    @Test
    void outboxInsertFailure_rollsBackTheEffect_noOrphanSuspension() {
        // Spy the outbox repo so insert() fails — the whole tx must roll back, leaving
        // NO access_suspension row (the two writes are coupled).
        NotificationOutboxRepository outbox = spy(new NotificationOutboxRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository.class)));
        doReturn(Mono.error(new RuntimeException("outbox boom")))
                .when(outbox).insert(anyString(), anyString(), anyString(), anyString(), any());
        SuspensionService svc = service(outbox, ticking());

        StepVerifier.create(svc.suspend(AccessSuspension.ROLE_PROFILE, "carol",
                        null, "abuse", "mod", SCOPE))
                .expectErrorMessage("outbox boom")
                .verify();

        // BOTH legs rolled back: no suspension, no outbox row.
        assertThat(suspensionCount()).isEqualTo(0);
        assertThat(outboxCount()).isEqualTo(0);
    }

    // ── EFFECT FAILURE: a failed effect write leaves NO outbox row ──────────
    @Test
    void effectWriteFailure_leavesNoOutboxRow() {
        // A spied AccessSuspensionRepository whose insertActive fails: the outbox insert
        // is downstream of it and must never run (and certainly never commit).
        AccessSuspensionRepository repo = spy(new AccessSuspensionRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.suspension.AccessSuspensionRowRepository.class)));
        doReturn(Mono.error(new RuntimeException("effect boom")))
                .when(repo).insertActive(anyString(), anyString(), anyString(), any(), anyBoolean(),
                        any(), anyString(), anyString());
        NotificationOutboxRepository outbox = spy(new NotificationOutboxRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository.class)));
        SuspensionService svc = new SuspensionService(repo, ticking(), outbox, tx());

        StepVerifier.create(svc.suspend(AccessSuspension.ROLE_PROFILE, "dave",
                        null, "abuse", "mod", SCOPE))
                .expectErrorMessage("effect boom")
                .verify();

        assertThat(outboxCount()).isEqualTo(0);
        assertThat(suspensionCount()).isEqualTo(0);
        // The outbox insert was never even attempted (effect failed first).
        verify(outbox, never()).insert(anyString(), anyString(), anyString(), anyString(), any());
    }

    // ── DEDUP: an idempotent re-ban writes no second effect + no second row ──
    @Test
    void reBanOfActiveTarget_isNoOp_doesNotDoubleInsertOutbox() {
        NotificationOutboxRepository outbox = new NotificationOutboxRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository.class));
        SuspensionService svc = service(outbox, ticking());

        AccessSuspension first = svc.suspend(AccessSuspension.ROLE_PROFILE, "erin",
                null, "abuse", "mod", SCOPE).block();
        // Re-ban the SAME target+role while still active → idempotent no-op (returns the
        // existing row), so NO new effect and NO new outbox row.
        AccessSuspension again = svc.suspend(AccessSuspension.ROLE_PROFILE, "erin",
                null, "abuse-again", "mod2", SCOPE).block();

        assertThat(again.id()).isEqualTo(first.id());
        assertThat(suspensionCount()).isEqualTo(1);
        assertThat(outboxCount()).isEqualTo(1);
    }

    // ── DEDUP at the DB level: the UNIQUE(source_table, source_id, category) ─
    @Test
    void uniqueConstraint_blocksASecondOutboxRowForTheSameEffect() {
        NotificationOutboxRepository outbox = new NotificationOutboxRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository.class));
        // First insert ok.
        assertThat(outbox.insert("brandx", NotificationOutbox.SOURCE_ACCESS_SUSPENSION,
                "fixed-id", NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION, "{}").block()).isEqualTo(1L);
        // Second insert with the same (source_table, source_id, category) → unique violation.
        StepVerifier.create(outbox.insert("brandx", NotificationOutbox.SOURCE_ACCESS_SUSPENSION,
                        "fixed-id", NotificationOutbox.CATEGORY_ACCOUNT_RESTRICTION, "{}"))
                .expectError()
                .verify();
        assertThat(outboxCount()).isEqualTo(1);
    }

    // ── SHIPS DARK: no delivery/cursor side-effect; only the (best-effort) tick ──
    @Test
    void shipsDark_noDeliveryRows_andOnlyTheReconcileTickIsCalled() {
        NotificationOutboxRepository outbox = new NotificationOutboxRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository.class));
        AccessSyncActions actions = ticking();
        SuspensionService svc = service(outbox, actions);

        svc.suspend(AccessSuspension.ROLE_PROFILE, "frank", null, "abuse", "mod", SCOPE).block();

        // The outbox row exists, but NOTHING consumes it: no delivery rows, no cursor rows.
        assertThat(outboxCount()).isEqualTo(1);
        assertThat(countOf("notification_delivery")).isEqualTo(0);
        assertThat(countOf("notification_cursor")).isEqualTo(0);
        // The only downstream interaction is the best-effort reconcile tick (NOT a
        // notification delivery call — there is no delivery path in this PR).
        verify(actions, atLeastOnce()).triggerTick();
    }

    /** Build a real scoped (non-superadmin) {@link PrincipalDomain} for {@code domain} from
     *  a validated-issuer JWT — the same mechanism the production controller uses, so
     *  the domain stamped on writes is genuinely scope-derived (never user-settable). */
    private static PrincipalDomain scope(String domain) {
        String issuer = "https://idp." + domain + ".example";
        DomainRegistry registry = new DomainRegistry("", issuer + "=" + domain);
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(java.time.Instant.now()).expiresAt(java.time.Instant.now().plusSeconds(3600))
                .subject("u").issuer(issuer).claim("roles", java.util.List.of("admin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                java.util.List.of(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, registry);
    }
}
