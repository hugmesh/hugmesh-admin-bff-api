package net.hugmesh.adminbff.backup;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PBKDF2 verifier behaviour: the right password re-derives to the stored verifier,
 * a wrong password does not, salts are random, and the verifier is one-way (it is
 * neither the password nor the data key). Constant-time compare is exercised via
 * matches().
 */
class BackupCryptoTest {

    private final BackupCrypto crypto = new BackupCrypto();

    @Test
    void verifier_matchesCorrectPassword_andRejectsWrong() {
        String salt = crypto.newSalt();
        String verifier = crypto.verifier("correct horse battery", salt);

        assertThat(crypto.matches("correct horse battery", salt, verifier)).isTrue();
        assertThat(crypto.matches("wrong password", salt, verifier)).isFalse();
    }

    @Test
    void salts_areRandom_andChangeTheVerifier() {
        String s1 = crypto.newSalt();
        String s2 = crypto.newSalt();
        assertThat(s1).isNotEqualTo(s2);
        assertThat(crypto.verifier("pw", s1)).isNotEqualTo(crypto.verifier("pw", s2));
    }

    @Test
    void verifier_isNotThePlaintextPassword() {
        String salt = crypto.newSalt();
        String verifier = crypto.verifier("s3cret-passphrase", salt);
        assertThat(verifier).doesNotContain("s3cret-passphrase");
    }

    @Test
    void matches_nullArguments_areSafelyFalse() {
        assertThat(crypto.matches(null, "salt", "v")).isFalse();
        assertThat(crypto.matches("pw", null, "v")).isFalse();
        assertThat(crypto.matches("pw", "salt", null)).isFalse();
    }
}
