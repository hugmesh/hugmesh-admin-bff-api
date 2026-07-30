package systems.hugmesh.adminbff.account;
import systems.hugmesh.authcore.account.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import systems.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * Band-150 MFA columns + the A2 carrier-agnostic session primitives over the real
 * Liquibase-applied H2: the dual-READ parity ({@code sessionOf("Bearer "+t)} and
 * {@code sessionOfToken(t)} resolve the SAME row), the MFA stamp/clear/state, and
 * {@code deleteSession} (logout) returning the account id then making the token unresolvable.
 */
@SpringBootTest(classes = AccountStoreMfaSessionTest.Boot.class)
@ActiveProfiles("test")
class AccountStoreMfaSessionTest extends AdminBffPostgresTestSupport {

    @org.springframework.boot.autoconfigure.SpringBootApplication
    static class Boot { }

    // Pre-existing red since #230: the per-package Boot scan picks up
    // AccountIssuerService, which needs a DomainRegistry this mini-context never
    // provided (context-load error). Same fix as AccountCasdoorSubServiceTest.
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    systems.hugmesh.commons.security.DomainRegistry domainRegistry;

    @Autowired DatabaseClient db;

    private AccountStore newStore() {
        AccountStore store = new AccountStore(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.authcore.account.AllowlistRepository.class), systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.authcore.account.AccountRowRepository.class), systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.authcore.account.BffSessionRepository.class), systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.authcore.account.NamespaceGrantRepository.class), "admin@hugmesh.systems");
        store.seedAdmins();
        return store;
    }

    @Test
    void dualReadParity_headerAndRawToken_sameRow() {
        AccountStore store = newStore();
        Account a = store.ensureAccount("google", "admin@hugmesh.systems").block();
        String token = store.newSession(a).block();
        // BOTH carriers resolve the SAME account.
        StepVerifier.create(store.sessionOf("Bearer " + token)).expectNext(a).verifyComplete();
        StepVerifier.create(store.sessionOfToken(token)).expectNext(a).verifyComplete();
        // a non-bff raw token is empty (fail-closed).
        StepVerifier.create(store.sessionOfToken("not-bff")).verifyComplete();
    }

    @Test
    void mfaState_defaultsFalse_thenStamp_thenClear() {
        AccountStore store = newStore();
        Account a = store.ensureAccount("google", "admin@hugmesh.systems").block();
        String token = store.newSession(a).block();

        // default: a fresh session is NOT mfa-satisfied (fail-closed default).
        AccountStore.MfaState before = store.mfaStateOf(token).block();
        assertThat(before).isNotNull();
        assertThat(before.satisfied()).isFalse();
        assertThat(before.satisfiedAt()).isNull();

        // stamp -> satisfied + a timestamp recorded.
        assertThat(store.stampMfaSatisfied(token, "webauthn").block()).isEqualTo(1L);
        AccountStore.MfaState stamped = store.mfaStateOf(token).block();
        assertThat(stamped.satisfied()).isTrue();
        assertThat(stamped.satisfiedAt()).isNotNull();

        // clear (single-use consume) -> back to not-satisfied, timestamp nulled.
        assertThat(store.clearMfaSatisfied(token).block()).isEqualTo(1L);
        AccountStore.MfaState cleared = store.mfaStateOf(token).block();
        assertThat(cleared.satisfied()).isFalse();
        assertThat(cleared.satisfiedAt()).isNull();
    }

    @Test
    void deleteSession_returnsAccountId_thenTokenUnresolvable() {
        AccountStore store = newStore();
        Account a = store.ensureAccount("google", "admin@hugmesh.systems").block();
        String token = store.newSession(a).block();

        StepVerifier.create(store.deleteSession(token)).expectNext(a.id()).verifyComplete();
        // gone: neither carrier resolves it now.
        StepVerifier.create(store.sessionOfToken(token)).verifyComplete();
        // idempotent: deleting again resolves to empty (no row).
        StepVerifier.create(store.deleteSession(token)).verifyComplete();
    }

    @Test
    void mfaStampAndState_unknownToken_safe() {
        AccountStore store = newStore();
        assertThat(store.stampMfaSatisfied("bff_unknown", "otp").block()).isEqualTo(0L);
        StepVerifier.create(store.mfaStateOf("bff_unknown")).verifyComplete();   // empty
        assertThat(store.stampMfaSatisfied("not-bff", "otp").block()).isEqualTo(0L);
    }
}
