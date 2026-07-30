package systems.hugmesh.adminbff.backup;

import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Password handling for encrypted backups. THE BFF NEVER STORES THE PLAINTEXT
 * PASSWORD and never persists the actual AES key.
 *
 * <p>Two distinct uses of the password, kept apart on purpose:
 * <ol>
 *   <li><b>Verifier</b> (this class) — a one-way PBKDF2-HMAC-SHA256 derivation
 *       (210 000 iterations, per-backup random salt) stored in
 *       {@code backup_history} as {@code verifier_salt} + {@code verifier}. On
 *       restore we re-derive from the supplied password and constant-time compare
 *       to confirm the right password BEFORE launching the restore worker. A
 *       mismatch is a clean 403 and the key is never revealed. The verifier is a
 *       KDF output, so it cannot be reversed to the password OR the data key.</li>
 *   <li><b>Data key</b> (NOT here) — the actual AES-256 key that encrypts the
 *       backup blob is derived INSIDE the worker by {@code openssl enc -aes-256-cbc
 *       -pbkdf2} from the same password (passed to the Job via an ephemeral,
 *       auto-deleted Kubernetes Secret — see {@code jobs/backup-job.yaml}). The
 *       BFF process therefore never holds the data key in memory.</li>
 * </ol>
 *
 * <p>PBKDF2-HMAC-SHA256 is used (not argon2id) because it ships in the JDK with no
 * extra dependency — argon2 would require BouncyCastle, which is not on the
 * classpath and would break the GraalVM native image. AES-256 + PBKDF2 matches
 * the platform's stated crypto direction (AES-256, strong KDF).
 */
@Component
public class BackupCrypto {

    /** OWASP-recommended PBKDF2-HMAC-SHA256 iteration floor (2023+). */
    static final int ITERATIONS = 210_000;
    static final int SALT_BYTES = 16;
    static final int KEY_BITS = 256;
    private static final String ALGO = "PBKDF2WithHmacSHA256";

    private final SecureRandom random = new SecureRandom();

    /** A fresh, base64-encoded random salt for a new encrypted backup. */
    public String newSalt() {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Derive the base64 PBKDF2 verifier of {@code password} under {@code saltB64}.
     * Stored at backup time; re-derived + compared at restore time. Never the data
     * key — only a proof the password is correct.
     */
    public String verifier(String password, String saltB64) {
        byte[] salt = Base64.getDecoder().decode(saltB64);
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_BITS);
            SecretKeyFactory f = SecretKeyFactory.getInstance(ALGO);
            byte[] dk = f.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(dk);
        } catch (Exception e) {
            // PBKDF2WithHmacSHA256 is a guaranteed JDK algorithm; a failure here is
            // a JVM-level fault, not a user error — surface it, never silently pass.
            throw new IllegalStateException("PBKDF2 derivation failed", e);
        }
    }

    /**
     * Constant-time check that {@code password} re-derives to the stored
     * {@code verifier} under {@code saltB64}. Constant-time so a wrong password
     * cannot be probed by response-timing.
     */
    public boolean matches(String password, String saltB64, String expectedVerifier) {
        if (password == null || saltB64 == null || expectedVerifier == null) return false;
        String actual = verifier(password, saltB64);
        return constantTimeEquals(actual.getBytes(StandardCharsets.UTF_8),
                expectedVerifier.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
