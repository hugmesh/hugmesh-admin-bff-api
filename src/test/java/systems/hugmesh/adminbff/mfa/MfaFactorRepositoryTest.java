package systems.hugmesh.adminbff.mfa;
import systems.hugmesh.authcore.mfa.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.adminbff.testutil.R2dbcRepos;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code mfa_factor} / {@code mfa_recovery_code} / {@code webauthn_credential} R2DBC
 * repositories over a Liquibase-applied H2 — proves the 151 changelog applies and the
 * OWNER-SCOPED predicates hold (the cross-user isolation keystone): every list/consume/
 * delete is keyed on owner, so subject A's queries never touch subject B's rows.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class MfaFactorRepositoryTest {

    @Autowired DatabaseClient db;

    private MfaFactorR2dbcRepository factors;
    private MfaRecoveryCodeR2dbcRepository codes;
    private WebAuthnCredentialR2dbcRepository creds;

    @BeforeEach
    void setup() {
        db.sql("DELETE FROM mfa_factor").fetch().rowsUpdated().block();
        db.sql("DELETE FROM mfa_recovery_code").fetch().rowsUpdated().block();
        db.sql("DELETE FROM webauthn_credential").fetch().rowsUpdated().block();
        factors = R2dbcRepos.of(db, MfaFactorR2dbcRepository.class);
        codes = R2dbcRepos.of(db, MfaRecoveryCodeR2dbcRepository.class);
        creds = R2dbcRepos.of(db, WebAuthnCredentialR2dbcRepository.class);
    }

    private MfaFactorRow totp(String owner, boolean enabled) {
        return new MfaFactorRow(UUID.randomUUID().toString(), owner, MfaFactorRow.TYPE_TOTP,
                "enc", enabled ? 100L : null, enabled, Instant.now(), true);
    }

    @Test
    void factor_listIsOwnerScoped_crossUserIsolation() {
        factors.save(totp("alice", true)).block();
        factors.save(totp("alice", false)).block();
        factors.save(totp("bob", true)).block();

        List<MfaFactorRow> aliceRows = factors.findByOwnerSubject("alice").collectList().block();
        assertThat(aliceRows).hasSize(2).allMatch(r -> r.ownerSubject().equals("alice"));
        // DENY: alice's query never returns bob's factor.
        assertThat(factors.findByOwnerSubject("bob").collectList().block())
                .hasSize(1).allMatch(r -> r.ownerSubject().equals("bob"));
    }

    @Test
    void enableTotp_andAdvanceCounter_areOwnerScoped() {
        MfaFactorRow row = totp("alice", false);
        factors.save(row).block();

        // bob cannot enable alice's factor (owner predicate -> 0 rows).
        assertThat(factors.enableTotp(row.id(), "bob", 5L).block()).isEqualTo(0L);
        assertThat(factors.enableTotp(row.id(), "alice", 5L).block()).isEqualTo(1L);

        // advance only moves forward; a replay (same/older step) updates 0 rows.
        assertThat(factors.advanceCounter(row.id(), "alice", 6L).block()).isEqualTo(1L);
        assertThat(factors.advanceCounter(row.id(), "alice", 6L).block()).isEqualTo(0L);
        assertThat(factors.advanceCounter(row.id(), "alice", 3L).block()).isEqualTo(0L);
    }

    @Test
    void deleteFactor_isOwnerScoped() {
        MfaFactorRow row = totp("alice", true);
        factors.save(row).block();
        assertThat(factors.deleteByIdAndOwner(row.id(), "bob").block()).isEqualTo(0L);
        assertThat(factors.deleteByIdAndOwner(row.id(), "alice").block()).isEqualTo(1L);
    }

    @Test
    void recoveryCode_consumeIsOneTime_andOwnerScoped() {
        String id = UUID.randomUUID().toString();
        codes.save(new MfaRecoveryCodeRow(id, "alice", "hash", false, Instant.now(), true)).block();

        assertThat(codes.findByOwnerSubjectAndUsedFalse("alice").collectList().block()).hasSize(1);
        // bob cannot consume alice's code.
        assertThat(codes.consume(id, "bob").block()).isEqualTo(0L);
        // one-time: first consume wins, second is a no-op.
        assertThat(codes.consume(id, "alice").block()).isEqualTo(1L);
        assertThat(codes.consume(id, "alice").block()).isEqualTo(0L);
        assertThat(codes.findByOwnerSubjectAndUsedFalse("alice").collectList().block()).isEmpty();
    }

    @Test
    void recoveryCode_deleteByOwner_onlyDeletesOwn() {
        codes.save(new MfaRecoveryCodeRow(UUID.randomUUID().toString(), "alice", "h", false, Instant.now(), true)).block();
        codes.save(new MfaRecoveryCodeRow(UUID.randomUUID().toString(), "bob", "h", false, Instant.now(), true)).block();
        codes.deleteByOwner("alice").block();
        assertThat(codes.findByOwnerSubjectAndUsedFalse("alice").collectList().block()).isEmpty();
        assertThat(codes.findByOwnerSubjectAndUsedFalse("bob").collectList().block()).hasSize(1);
    }

    @Test
    void webauthnCredential_signCountAdvancesMonotonically_cloneRejected() {
        String id = UUID.randomUUID().toString();
        creds.save(new WebAuthnCredentialRow(id, "alice", "credId", "cose", 10L, "usb", true,
                Instant.now(), true)).block();

        // bob cannot advance alice's credential.
        assertThat(creds.advanceSignCount(id, "bob", 11L).block()).isEqualTo(0L);
        // a strictly greater count advances.
        assertThat(creds.advanceSignCount(id, "alice", 11L).block()).isEqualTo(1L);
        // a stale/equal count (clone / replay) updates 0 rows.
        assertThat(creds.advanceSignCount(id, "alice", 11L).block()).isEqualTo(0L);
        assertThat(creds.advanceSignCount(id, "alice", 5L).block()).isEqualTo(0L);
    }

    @Test
    void webauthnCredential_findByCredentialId_isUnique() {
        creds.save(new WebAuthnCredentialRow(UUID.randomUUID().toString(), "alice", "credX", "cose",
                0L, null, true, Instant.now(), true)).block();
        assertThat(creds.findByCredentialId("credX").block()).isNotNull();
        assertThat(creds.findByCredentialId("nope").block()).isNull();
    }
}
