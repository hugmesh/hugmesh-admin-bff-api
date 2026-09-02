package net.hugmesh.adminbff.account;
import net.hugmesh.authcore.account.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * Two-stage lifecycle, invite gating, admin-role derivation, session resolve —
 * now against the DURABLE R2DBC-backed store over a Liquibase-applied H2. Proves
 * the rows survive a "restart" (a second AccountStore instance over the SAME
 * datastore sees the persisted state — the cross-replica / durability property).
 */
@SpringBootTest(classes = AccountStoreTest.Boot.class)
@ActiveProfiles("test")
class AccountStoreTest extends AdminBffPostgresTestSupport {

    @org.springframework.boot.autoconfigure.SpringBootApplication
    static class Boot { }

    // Pre-existing red since #230: the per-package Boot scan picks up
    // AccountIssuerService, which needs a DomainRegistry this mini-context never
    // provided (context-load error). Same fix as AccountCasdoorSubServiceTest.
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    net.hugmesh.commons.security.DomainRegistry domainRegistry;

    @Autowired DatabaseClient db;

    private AccountStore newStore() {
        AccountStore store = new AccountStore(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AllowlistRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AccountRowRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.BffSessionRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.NamespaceGrantRepository.class), "admin@hugmesh.net");
        store.seedAdmins();   // @PostConstruct equivalent — seed the durable allowlist
        return store;
    }

    @Test
    void seedAdminIsInvitedAndGetsAdminRole() {
        AccountStore store = newStore();
        // Domain-scoped gate (auth-core issue #1): seedAdmins stamps DEFAULT_DOMAIN, so that
        // is the domain the seeded row answers for — and only that one. The deprecated
        // unscoped overload ("invited in ANY domain") has no callers left in this repo.
        StepVerifier.create(store.isEmailInvited("admin@hugmesh.net", AccountStore.DEFAULT_DOMAIN))
                .expectNext(true).verifyComplete();
        StepVerifier.create(store.isEmailInvited("admin@hugmesh.net", "some-other-brand"))
                .expectNext(false).verifyComplete();
        Account a = store.ensureAccount("google", "admin@hugmesh.net").block();
        assertThat(a.roles()).containsExactly("user", "admin");
        assertThat(a.isAdmin()).isTrue();
        assertThat(a.registrationComplete()).isFalse();
    }

    @Test
    void nonAdminInvitedEmailGetsUserRoleOnly() {
        AccountStore store = newStore();
        store.inviteEmail("friend@gmail.com", "default").block();
        Account a = store.ensureAccount("google", "friend@gmail.com").block();
        assertThat(a.roles()).containsExactly("user");
        assertThat(a.isAdmin()).isFalse();
    }

    @Test
    void ensureAccount_withRoles_createsWithGivenRoles() {
        AccountStore store = newStore();
        Account a = store.ensureAccount("casdoor", "e2e-admin", List.of("admin", "user")).block();
        assertThat(a.roles()).containsExactly("admin", "user");
        assertThat(a.isAdmin()).isTrue();
        assertThat(a.registrationComplete()).isFalse();
    }

    @Test
    void ensureAccount_withRoles_syncsRolesOnExistingAccount() {
        // The core fix: a native-login account, once created with the legacy "user"-only
        // default, must pick up its REAL Casdoor roles on the NEXT ensureAccount call rather
        // than staying frozen — the whole point of syncing on every login, not just creation.
        AccountStore store = newStore();
        Account created = store.ensureAccount("casdoor", "e2e-mod", null).block();
        assertThat(created.roles()).containsExactly("user");

        Account synced = store.ensureAccount("casdoor", "e2e-mod", List.of("mod", "user")).block();
        assertThat(synced.roles()).containsExactlyInAnyOrder("mod", "user");
        assertThat(synced.id()).isEqualTo(created.id());
    }

    @Test
    void ensureAccount_withRoles_syncDoesNotResetRegistrationComplete() {
        AccountStore store = newStore();
        Account a = store.ensureAccount("casdoor", "e2e-user", List.of("user")).block();
        store.markComplete(a).block();

        Account resynced = store.ensureAccount("casdoor", "e2e-user", List.of("user", "matrix")).block();
        assertThat(resynced.registrationComplete()).isTrue();
        assertThat(resynced.roles()).containsExactlyInAnyOrder("user", "matrix");
    }

    @Test
    void ensureAccount_nullOrEmptyRoles_fallsBackToLegacyDefault() {
        AccountStore store = newStore();
        // "casdoor" provider is never in the google-admin-emails allowlist path, so both
        // null and empty roles land on the plain "user" legacy default.
        Account viaNull = store.ensureAccount("casdoor", "e2e-plain-a", null).block();
        assertThat(viaNull.roles()).containsExactly("user");
        Account viaEmpty = store.ensureAccount("casdoor", "e2e-plain-b", List.of()).block();
        assertThat(viaEmpty.roles()).containsExactly("user");
    }

    @Test
    void sessionResolvesAccount_andSurvivesRestart() {
        AccountStore store = newStore();
        Account a = store.ensureAccount("google", "admin@hugmesh.net").block();
        String token = store.newSession(a).block();

        StepVerifier.create(store.sessionOf("Bearer " + token)).expectNext(a).verifyComplete();
        StepVerifier.create(store.sessionOf("Bearer bff_bogus")).verifyComplete();   // empty
        StepVerifier.create(store.sessionOf(null)).verifyComplete();
        StepVerifier.create(store.sessionOf("Basic xyz")).verifyComplete();

        // "Restart": a brand-new store over the SAME durable datastore still
        // resolves the session — the in-memory-map-loses-state-on-restart bug fixed.
        AccountStore afterRestart = new AccountStore(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AllowlistRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AccountRowRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.BffSessionRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.NamespaceGrantRepository.class), "admin@hugmesh.net");
        StepVerifier.create(afterRestart.sessionOf("Bearer " + token)).expectNext(a).verifyComplete();
    }

    /**
     * Entropy hardening: the opaque session token's random body must be >=32 bytes
     * (256 bits) of CSPRNG, base64url-encoded without padding (was a truncated
     * ~8-byte/10-char value). Asserts the exact encoded length, the URL-safe
     * charset, and uniqueness across a large sample (no collisions = real entropy).
     * Pure-RNG: no DB needed, so it runs even without a datastore.
     */
    @Test
    void randomToken_isLongUrlSafeCsprng() {
        // 32 bytes base64url (no padding) == ceil(32 * 4 / 3) == 43 chars.
        int expectedLen = (AccountStore.SESSION_TOKEN_BYTES + 2) / 3 * 4
                - (3 - AccountStore.SESSION_TOKEN_BYTES % 3) % 3;
        assertThat(AccountStore.SESSION_TOKEN_BYTES).isGreaterThanOrEqualTo(32);

        java.util.Set<String> seen = new java.util.HashSet<>();
        for (int i = 0; i < 10_000; i++) {
            String t = AccountStore.randomToken();
            // Length: >=32 bytes of entropy => >=43 base64url chars, exactly expectedLen here.
            assertThat(t).hasSize(expectedLen);
            assertThat(expectedLen).isGreaterThanOrEqualTo(43);
            // Charset: base64url alphabet only, never '+', '/', or '=' padding.
            assertThat(t).matches("^[A-Za-z0-9_-]+$");
            assertThat(t).doesNotContain("+", "/", "=");
            // Uniqueness: a CSPRNG of this width must not collide across the sample.
            assertThat(seen.add(t)).as("token %s must be unique", t).isTrue();
        }

        // Full token shape: the 'bff_' prefix is preserved and fits varchar(64).
        AccountStore store = newStore();
        Account a = store.ensureAccount("google", "admin@hugmesh.net").block();
        String full = store.newSession(a).block();
        assertThat(full).startsWith("bff_");
        assertThat(full.length()).isLessThanOrEqualTo(64);
        assertThat(full.substring("bff_".length())).hasSize(expectedLen);
    }

    @Test
    void markComplete_flipsFlag_durably() {
        AccountStore store = newStore();
        Account a = store.ensureAccount("discord", "bob").block();
        Account done = store.markComplete(a).block();
        assertThat(done.registrationComplete()).isTrue();
        assertThat(store.account(a.id()).block().registrationComplete()).isTrue();
        // New store sees the persisted completion (durable across replicas).
        AccountStore other = new AccountStore(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AllowlistRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.AccountRowRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.BffSessionRepository.class), net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.authcore.account.NamespaceGrantRepository.class), "admin@hugmesh.net");
        assertThat(other.account(a.id()).block().registrationComplete()).isTrue();
    }

    @Test
    void namespacesForAdminAreAll_grantsForUsers() {
        AccountStore store = newStore();
        Account admin = store.ensureAccount("google", "admin@hugmesh.net").block();
        assertThat(store.namespacesFor(admin).block())
                .containsExactlyElementsOf(AccountStore.NAMESPACES);

        store.inviteDiscord("bob", "default").block();
        Account bob = store.ensureAccount("discord", "bob").block();
        assertThat(store.namespacesFor(bob).block()).isEmpty();
        store.grant(bob.id(), "observability", "default").block();
        assertThat(store.namespacesFor(bob).block()).containsExactly("observability");
    }

    @Test
    void allGrants_groupsNamespacesPerUser() {
        AccountStore store = newStore();
        store.grant("carol", "observability", "default").block();
        store.grant("carol", "hugmesh-games", "default").block();
        List<?> grants = store.allGrants().block();
        assertThat(grants).anySatisfy(g -> {
            @SuppressWarnings("unchecked")
            var m = (java.util.Map<String, Object>) g;
            if ("carol".equals(m.get("user"))) {
                @SuppressWarnings("unchecked")
                List<String> ns = (List<String>) m.get("namespaces");
                assertThat(ns).containsExactlyInAnyOrder("observability", "hugmesh-games");
            }
        });
    }
}
