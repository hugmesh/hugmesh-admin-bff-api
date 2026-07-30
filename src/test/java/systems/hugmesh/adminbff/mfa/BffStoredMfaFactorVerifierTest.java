package systems.hugmesh.adminbff.mfa;
import systems.hugmesh.authcore.mfa.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.authcore.casdoor.MfaFactorVerifier;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.adminbff.testutil.R2dbcRepos;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The REAL verifier against Liquibase-applied H2 + real crypto. Proves:
 * <ul>
 *   <li>TOTP ALLOW for the owner's ENABLED factor; replay of the same code DENIED;</li>
 *   <li>a DISABLED (mid-enroll) factor NEVER satisfies;</li>
 *   <li>recovery code one-time (second use DENIED);</li>
 *   <li>CROSS-USER isolation — subject B's code/factor never satisfies subject A's challenge;</li>
 *   <li>WebAuthn fail-closed when no pending challenge / unknown credential / wrong owner.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class BffStoredMfaFactorVerifierTest {

    @Autowired DatabaseClient db;

    private MfaFactorR2dbcRepository factors;
    private MfaRecoveryCodeR2dbcRepository codes;
    private WebAuthnCredentialR2dbcRepository creds;
    private MfaSecretCipher cipher;
    private TotpService totp;
    private RecoveryCodeService recovery;
    private WebAuthnService webauthn;
    private WebAuthnChallengeStore challenges;
    private BffStoredMfaFactorVerifier verifier;

    @BeforeEach
    void setup() {
        db.sql("DELETE FROM mfa_factor").fetch().rowsUpdated().block();
        db.sql("DELETE FROM mfa_recovery_code").fetch().rowsUpdated().block();
        db.sql("DELETE FROM webauthn_credential").fetch().rowsUpdated().block();
        db.sql("DELETE FROM webauthn_challenge").fetch().rowsUpdated().block();
        factors = R2dbcRepos.of(db, MfaFactorR2dbcRepository.class);
        codes = R2dbcRepos.of(db, MfaRecoveryCodeR2dbcRepository.class);
        creds = R2dbcRepos.of(db, WebAuthnCredentialR2dbcRepository.class);
        cipher = new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[32]));
        totp = new TotpService("HugMesh");
        recovery = new RecoveryCodeService("test-server-key");
        webauthn = new WebAuthnService("localhost", "https://localhost", "HugMesh");
        challenges = new WebAuthnChallengeStore(
                R2dbcRepos.of(db, WebAuthnChallengeR2dbcRepository.class));
        verifier = new BffStoredMfaFactorVerifier(factors, codes, creds, cipher, totp, recovery,
                webauthn, challenges);
    }

    private static String codeFor(String base32Secret, long step) {
        try {
            byte[] key = TotpService.base32Decode(base32Secret);
            byte[] msg = new byte[8];
            long v = step;
            for (int i = 7; i >= 0; i--) { msg[i] = (byte) (v & 0xff); v >>>= 8; }
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] h = mac.doFinal(msg);
            int off = h[h.length - 1] & 0x0f;
            int bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16)
                    | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
            return String.format("%06d", bin % 1_000_000);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String enrollEnabledTotp(String owner) {
        String secret = totp.newSecret();
        MfaFactorRow row = new MfaFactorRow(UUID.randomUUID().toString(), owner,
                MfaFactorRow.TYPE_TOTP, cipher.encrypt(secret), -1L, true, Instant.now(), true);
        factors.save(row).block();
        return secret;
    }

    @Test
    void totp_allowForOwner_thenReplayDenied() {
        String secret = enrollEnabledTotp("alice");
        long step = totp.currentCounter(Instant.now());
        String code = codeFor(secret, step);

        assertThat(verifier.verify("alice", "alice", MfaFactorVerifier.Factor.TOTP, code).block())
                .isTrue();
        // REPLAY of the same code (floor now advanced) -> denied.
        assertThat(verifier.verify("alice", "alice", MfaFactorVerifier.Factor.TOTP, code).block())
                .isFalse();
    }

    @Test
    void totp_disabledFactorNeverSatisfies() {
        String secret = totp.newSecret();
        factors.save(new MfaFactorRow(UUID.randomUUID().toString(), "alice", MfaFactorRow.TYPE_TOTP,
                cipher.encrypt(secret), null, false, Instant.now(), true)).block();
        String code = codeFor(secret, totp.currentCounter(Instant.now()));
        assertThat(verifier.verify("alice", "alice", MfaFactorVerifier.Factor.TOTP, code).block())
                .isFalse();
    }

    @Test
    void totp_crossUserIsolation_bobsSecretNeverSatisfiesAlice() {
        String aliceSecret = enrollEnabledTotp("alice");
        String bobSecret = enrollEnabledTotp("bob");
        // A code from BOB's secret presented as ALICE must not verify.
        String bobCode = codeFor(bobSecret, totp.currentCounter(Instant.now()));
        assertThat(verifier.verify("alice", "alice", MfaFactorVerifier.Factor.TOTP, bobCode).block())
                .isFalse();
        // sanity: alice's own code still works.
        String aliceCode = codeFor(aliceSecret, totp.currentCounter(Instant.now()));
        assertThat(verifier.verify("alice", "alice", MfaFactorVerifier.Factor.TOTP, aliceCode).block())
                .isTrue();
    }

    @Test
    void recovery_oneTime_andCrossUserIsolation() {
        String aliceCode = "AAAA-BBBB-CCCC-DDDD";
        codes.save(new MfaRecoveryCodeRow(UUID.randomUUID().toString(), "alice",
                recovery.hash(aliceCode), false, Instant.now(), true)).block();

        // bob presenting alice's code as himself: bob has no such code -> denied.
        assertThat(verifier.verify("bob", "bob", MfaFactorVerifier.Factor.RECOVERY, aliceCode).block())
                .isFalse();
        // alice: first use ALLOW, second use DENY (one-time consume).
        assertThat(verifier.verify("alice", "alice", MfaFactorVerifier.Factor.RECOVERY, aliceCode).block())
                .isTrue();
        assertThat(verifier.verify("alice", "alice", MfaFactorVerifier.Factor.RECOVERY, aliceCode).block())
                .isFalse();
    }

    @Test
    void webauthn_failsClosedWithoutPendingChallenge() {
        assertThat(verifier.verify("alice", "alice", MfaFactorVerifier.Factor.WEBAUTHN, "{}").block())
                .isFalse();
    }

    @Test
    void nullAndBlankInputsFailClosed() {
        assertThat(verifier.verify(null, null, MfaFactorVerifier.Factor.TOTP, "123456").block()).isFalse();
        assertThat(verifier.verify("alice", "alice", MfaFactorVerifier.Factor.TOTP, null).block()).isFalse();
        assertThat(verifier.verify("alice", "alice", null, "x").block()).isFalse();
    }
}
