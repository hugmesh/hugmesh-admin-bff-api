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
 * Proves the API↔DB parity constraints from changeset 007 actually reject a bad
 * write at the DATABASE, over the SAME H2 (PostgreSQL-compat) store the real
 * Liquibase changelog is applied to. These are the writes that BYPASS the
 * controller (a future code path / manual INSERT) — the threat the DB-level CHECK/FK
 * defends against. Each "bad" insert must error; the matching "good" insert must
 * succeed (so the constraint isn't over-tight).
 */
@SpringBootTest(classes = DataConstraintsTest.Boot.class)
@ActiveProfiles("test")
class DataConstraintsTest extends AdminBffPostgresTestSupport {

    @org.springframework.boot.autoconfigure.SpringBootApplication
    static class Boot { }

    // Pre-existing red since #230: the per-package Boot scan picks up
    // AccountIssuerService, which needs a DomainRegistry this mini-context never
    // provided (context-load error). Same fix as AccountCasdoorSubServiceTest.
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    net.hugmesh.commons.security.DomainRegistry domainRegistry;

    @Autowired DatabaseClient db;

    // ── allowlist.provider CHECK ────────────────────────────────────────
    @Test
    void allowlist_badProvider_rejected() {
        StepVerifier.create(db.sql("INSERT INTO allowlist (provider, handle) VALUES ('twitter', 'x')")
                        .fetch().rowsUpdated())
                .expectError().verify();
    }

    @Test
    void allowlist_goodProvider_accepted() {
        StepVerifier.create(db.sql("INSERT INTO allowlist (provider, handle) VALUES ('discord', 'ok-handle')")
                        .fetch().rowsUpdated())
                .assertNext(n -> org.assertj.core.api.Assertions.assertThat(n).isEqualTo(1L))
                .verifyComplete();
    }

    // ── account.provider + account.roles CHECK ──────────────────────────
    @Test
    void account_badProvider_rejected() {
        StepVerifier.create(insertAccount("twitter:x", "twitter", "x", "user").fetch().rowsUpdated())
                .expectError().verify();
    }

    @Test
    void account_richRoles_nowAccepted() {
        // ck_account_roles (2-value 'user'/'user,admin' enum) was DROPPED by changeset 260 —
        // the native-login role sync (AccountStore.ensureAccount(provider, handle, roles))
        // legitimately writes the full platform role vocabulary here now, not just
        // admin/user. See 260-account-roles-check-relax.xml for the full rationale.
        StepVerifier.create(insertAccount("google:rolebad", "google", "rolebad", "superadmin,mod,matrix")
                        .fetch().rowsUpdated())
                .assertNext(n -> org.assertj.core.api.Assertions.assertThat(n).isEqualTo(1L))
                .verifyComplete();
    }

    @Test
    void account_goodProviderAndRoles_accepted() {
        StepVerifier.create(insertAccount("google:good", "google", "good", "user,admin").fetch().rowsUpdated())
                .assertNext(n -> org.assertj.core.api.Assertions.assertThat(n).isEqualTo(1L))
                .verifyComplete();
    }

    // ── namespace_grant.namespace CHECK ─────────────────────────────────
    @Test
    void namespaceGrant_badNamespace_rejected() {
        StepVerifier.create(db.sql("INSERT INTO namespace_grant (grantee, namespace) VALUES ('bob', 'nope')")
                        .fetch().rowsUpdated())
                .expectError().verify();
    }

    @Test
    void namespaceGrant_goodNamespace_accepted() {
        StepVerifier.create(db.sql("INSERT INTO namespace_grant (grantee, namespace) VALUES ('bob', 'observability')")
                        .fetch().rowsUpdated())
                .assertNext(n -> org.assertj.core.api.Assertions.assertThat(n).isEqualTo(1L))
                .verifyComplete();
    }

    // ── bff_session.account_id FK ───────────────────────────────────────
    @Test
    void bffSession_orphanAccount_rejectedByFk() {
        StepVerifier.create(db.sql("INSERT INTO bff_session (token, account_id, expires_at) "
                                + "VALUES ('bff_orphan', 'google:does-not-exist', now())")
                        .fetch().rowsUpdated())
                .expectError().verify();
    }

    @Test
    void bffSession_withRealAccount_accepted() {
        insertAccount("google:sess", "google", "sess", "user").fetch().rowsUpdated().block();
        StepVerifier.create(db.sql("INSERT INTO bff_session (token, account_id, expires_at) "
                                + "VALUES ('bff_ok', 'google:sess', now())")
                        .fetch().rowsUpdated())
                .assertNext(n -> org.assertj.core.api.Assertions.assertThat(n).isEqualTo(1L))
                .verifyComplete();
    }

    // ── gateway_route_access non-blank CHECK ────────────────────────────
    @Test
    void routeAccess_blankRole_rejected() {
        StepVerifier.create(db.sql("INSERT INTO gateway_route_access "
                                + "(id, gateway, url_pattern, role, allow) "
                                + "VALUES (gen_random_uuid(), 'gw', '/api/**', '   ', true)")
                        .fetch().rowsUpdated())
                .expectError().verify();
    }

    private DatabaseClient.GenericExecuteSpec insertAccount(String id, String provider, String handle, String roles) {
        return db.sql("INSERT INTO account (id, provider, handle, registration_complete, roles) "
                        + "VALUES (:id, :p, :h, false, :r)")
                .bind("id", id).bind("p", provider).bind("h", handle).bind("r", roles);
    }
}
