package net.hugmesh.adminbff.account;
import net.hugmesh.authcore.account.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * Drives {@link AccountCasdoorSubService} against a REAL (Testcontainers) Postgres with
 * the production changelog applied — same base + wiring idiom as {@link
 * AccountLocalpartServiceTest} — so Liquibase changeset 292 ({@code account.casdoor_sub})
 * and the service's stamp/read logic are proven to work TOGETHER (the mock-based
 * {@code InternalAccountControllerTest} coverage proves only the controller-level
 * extraction/plumbing). The A5 part-B contract under test: a stamped row reads its UUID
 * back for introspect; an unstamped (legacy / invite-provider) row reads back EMPTY —
 * which introspect surfaces as {@code casdoorSub: null} and the gateway degrades on.
 */
@SpringBootTest(classes = AccountCasdoorSubServiceTest.Boot.class)
@ActiveProfiles("test")
class AccountCasdoorSubServiceTest extends AdminBffPostgresTestSupport {

    @org.springframework.boot.autoconfigure.SpringBootApplication
    static class Boot { }

    // The per-package Boot scan picks up AccountIssuerService, which since #230 takes a
    // DomainRegistry the mini-context never provided — the whole context failed to load
    // (pre-existing red, unrelated to what each test here drives). The override registers
    // the bean; the tests construct their own collaborators by hand as before.
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    net.hugmesh.commons.security.DomainRegistry domainRegistry;

    @Autowired DatabaseClient db;

    private static final String SUB = "2f3a9c1e-7b4d-4e08-9a21-5c6d7e8f9a0b";

    private AccountStore newAccountStore() {
        return new AccountStore(
                net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, AllowlistRepository.class),
                net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, AccountRowRepository.class),
                net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, BffSessionRepository.class),
                net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, NamespaceGrantRepository.class),
                "admin@hugmesh.net");
    }

    private AccountCasdoorSubService newCasdoorSubs() {
        return new AccountCasdoorSubService(
                net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, AccountCasdoorSubRepository.class));
    }

    /** Fresh mint shape: stamp writes the UUID onto the real column; the read returns it. */
    @Test
    void stamp_thenRead_roundTripsAgainstRealColumn() {
        AccountStore accounts = newAccountStore();
        AccountCasdoorSubService subs = newCasdoorSubs();

        Account a = accounts.ensureAccount("casdoor", "sub-alice@x.com").block();

        StepVerifier.create(subs.stamp(a.id(), SUB)).verifyComplete();
        StepVerifier.create(subs.casdoorSubOf(a.id())).expectNext(SUB).verifyComplete();
    }

    /** Legacy shape: a row the mint path never stamped (pre-292 / invite provider) reads
     *  back EMPTY — introspect then returns casdoorSub = null (the degrade contract). */
    @Test
    void unstampedRow_readsBackEmpty() {
        AccountStore accounts = newAccountStore();
        AccountCasdoorSubService subs = newCasdoorSubs();

        Account legacy = accounts.ensureAccount("google", "sub-legacy@x.com").block();
        StepVerifier.create(subs.casdoorSubOf(legacy.id())).verifyComplete();
    }

    /** Repeat sign-in shape: the second stamp with the SAME value fast-paths (no write) and
     *  the persisted value is unchanged; a null/blank stamp NEVER clears a stored value. */
    @Test
    void repeatStamp_isIdempotent_andNullStampNeverClears() {
        AccountStore accounts = newAccountStore();
        AccountCasdoorSubService subs = newCasdoorSubs();

        Account a = accounts.ensureAccount("casdoor", "sub-bob@x.com").block();

        StepVerifier.create(subs.stamp(a.id(), SUB)).verifyComplete();
        StepVerifier.create(subs.stamp(a.id(), SUB)).verifyComplete();      // fast path
        StepVerifier.create(subs.stamp(a.id(), null)).verifyComplete();     // documented no-op
        StepVerifier.create(subs.stamp(a.id(), "  ")).verifyComplete();     // documented no-op
        StepVerifier.create(subs.casdoorSubOf(a.id())).expectNext(SUB).verifyComplete();
    }

    /** Casdoor re-keys the subject (e.g. an email change mints a NEW account id, same
     *  human/UUID): the sub is deliberately NOT unique, so stamping the same UUID onto a
     *  second row must succeed (deny-wins pin matching makes the shared id strictly safe;
     *  a UNIQUE constraint here would 500 the re-keyed login — see the changeset comment). */
    @Test
    void sameSubOnTwoAccountRows_isAllowed_noUniqueConstraint() {
        AccountStore accounts = newAccountStore();
        AccountCasdoorSubService subs = newCasdoorSubs();

        Account first = accounts.ensureAccount("casdoor", "sub-carol@old.com").block();
        Account second = accounts.ensureAccount("casdoor", "sub-carol@new.com").block();

        StepVerifier.create(subs.stamp(first.id(), SUB)).verifyComplete();
        StepVerifier.create(subs.stamp(second.id(), SUB)).verifyComplete();
        StepVerifier.create(subs.casdoorSubOf(first.id())).expectNext(SUB).verifyComplete();
        StepVerifier.create(subs.casdoorSubOf(second.id())).expectNext(SUB).verifyComplete();
    }
}
