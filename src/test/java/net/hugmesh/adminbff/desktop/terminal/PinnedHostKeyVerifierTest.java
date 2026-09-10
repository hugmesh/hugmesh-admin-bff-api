package net.hugmesh.adminbff.desktop.terminal;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.SecurityUtils;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-pins the MANDATORY, FAIL-CLOSED host-key behavior of {@link PinnedHostKeyVerifier} — the
 * core security guarantee of the real dial. There is NO TOFU: a verifier ONLY ever returns
 * {@code true} for the EXACT pinned fingerprint of the presented key, and returns {@code false}
 * (which aborts the sshj transport before auth) for a mismatch or an absent pin.
 */
class PinnedHostKeyVerifierTest {

    private static PublicKey rsaKey() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        return kp.getPublic();
    }

    @Test
    void accepts_whenPresentedKeyMatchesPinnedFingerprint() throws Exception {
        PublicKey host = rsaKey();
        String pinned = SecurityUtils.getFingerprint(host); // the legit node's host-key fp
        PinnedHostKeyVerifier verifier = new PinnedHostKeyVerifier("dev-1", pinned);

        assertThat(verifier.verify("dev-1.mesh", 22, host)).isTrue();
    }

    @Test
    void rejects_whenPresentedKeyDoesNotMatchPin() throws Exception {
        PublicKey pinnedHost = rsaKey();
        PublicKey attackerHost = rsaKey(); // a DIFFERENT key (e.g. MITM / rotated without re-pin)
        String pinned = SecurityUtils.getFingerprint(pinnedHost);
        PinnedHostKeyVerifier verifier = new PinnedHostKeyVerifier("dev-1", pinned);

        // The attacker's key fingerprint differs -> REFUSE (no TOFU, no auto-accept).
        assertThat(verifier.verify("dev-1.mesh", 22, attackerHost)).isFalse();
    }

    @Test
    void rejects_whenPinIsAbsentOrBlank() throws Exception {
        PublicKey host = rsaKey();
        assertThat(new PinnedHostKeyVerifier("dev-1", null).verify("dev-1.mesh", 22, host)).isFalse();
        assertThat(new PinnedHostKeyVerifier("dev-1", "  ").verify("dev-1.mesh", 22, host)).isFalse();
    }

    @Test
    void accepts_md5LabelledPinForm() throws Exception {
        PublicKey host = rsaKey();
        // Pin stored WITH the legacy "MD5:" label — must still match the bare fingerprint.
        String pinned = "MD5:" + SecurityUtils.getFingerprint(host);
        assertThat(new PinnedHostKeyVerifier("dev-1", pinned).verify("dev-1.mesh", 22, host)).isTrue();
    }

    /** The OpenSSH {@code SHA256:base64(nopadding)} fingerprint a node/seed PR would emit
     *  (e.g. {@code ssh-keygen -lf}) — computed here INDEPENDENTLY of the verifier, in the
     *  canonical OpenSSH form: an uppercase {@code SHA256:} label and STANDARD (mixed-case,
     *  unpadded) base64, NOT lower-cased. Exercises the verifier's sha256Fingerprint accept path. */
    private static String openSshSha256Fp(PublicKey key) throws Exception {
        byte[] wire = new Buffer.PlainBuffer().putPublicKey(key).getCompactData();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(wire);
        return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest);
    }

    @Test
    void accepts_sha256FingerprintPinForm_matchingKey() throws Exception {
        PublicKey host = rsaKey();
        // Pin stored as the modern OpenSSH "SHA256:<base64>" form (uppercase label, mixed-case
        // base64) — must match via the verifier's locally-computed SHA256 fingerprint path.
        String pinned = openSshSha256Fp(host);
        assertThat(pinned).startsWith("SHA256:");
        assertThat(new PinnedHostKeyVerifier("dev-1", pinned).verify("dev-1.mesh", 22, host)).isTrue();
    }

    @Test
    void rejects_sha256FingerprintPinForm_mismatchedKey() throws Exception {
        PublicKey pinnedHost = rsaKey();
        PublicKey attackerHost = rsaKey(); // a DIFFERENT key presented at dial time
        // Non-vacuousness guard for the accept test above: the SHA256-form pin of one key must
        // NOT verify a different presented key (no TOFU, no auto-accept on the SHA256 path).
        String pinned = openSshSha256Fp(pinnedHost);
        assertThat(new PinnedHostKeyVerifier("dev-1", pinned)
                .verify("dev-1.mesh", 22, attackerHost)).isFalse();
    }

    // ── H1: base64 is CASE-SIGNIFICANT; only the algorithm LABEL may be case-folded ──────────

    /** The pre-fix verifier lower-cased BOTH the pin and the computed SHA-256 digest, so a pin
     *  differing from the real fingerprint only in letter case still verified — folding 52 of
     *  base64's 64 symbols onto 26. A case-mangled pin is a DIFFERENT pin and must REFUSE. */
    @Test
    void rejects_sha256PinThatDiffersFromTheRealFingerprintOnlyInCase() throws Exception {
        PublicKey host = rsaKey();
        String real = openSshSha256Fp(host);                 // "SHA256:<mixed-case base64>"
        String digest = real.substring("SHA256:".length());
        String mangled = "SHA256:" + digest.toLowerCase(java.util.Locale.ROOT);
        // Guard the guard: only run the assertion on a digest that actually HAS an upper-case
        // letter to mangle (an all-lower/all-digit base64 would make this vacuous).
        assertThat(digest).isNotEqualTo(digest.toLowerCase(java.util.Locale.ROOT));

        assertThat(new PinnedHostKeyVerifier("dev-1", mangled).verify("dev-1.mesh", 22, host))
                .isFalse();
    }

    /** The same in the other direction: an UPPER-cased digest is also a different pin. */
    @Test
    void rejects_sha256PinUpperCased() throws Exception {
        PublicKey host = rsaKey();
        String digest = openSshSha256Fp(host).substring("SHA256:".length());
        assertThat(digest).isNotEqualTo(digest.toUpperCase(java.util.Locale.ROOT));
        assertThat(new PinnedHostKeyVerifier("dev-1", "SHA256:" + digest.toUpperCase(java.util.Locale.ROOT))
                .verify("dev-1.mesh", 22, host)).isFalse();
    }

    /** MD5 fingerprints are colon-HEX, where case carries no information — those stay
     *  case-insensitive, so an upper-cased legacy pin keeps working. */
    @Test
    void accepts_md5PinRegardlessOfHexCase() throws Exception {
        PublicKey host = rsaKey();
        String md5 = SecurityUtils.getFingerprint(host);
        assertThat(new PinnedHostKeyVerifier("dev-1", md5.toUpperCase(java.util.Locale.ROOT))
                .verify("dev-1.mesh", 22, host)).isTrue();
    }

    /** A LABELLED pin is matched ONLY against that algorithm's form — a "SHA256:"-labelled pin
     *  holding the MD5 hex must not be honoured by the MD5 leg. */
    @Test
    void rejects_sha256LabelledPinHoldingTheMd5Digest() throws Exception {
        PublicKey host = rsaKey();
        String md5 = SecurityUtils.getFingerprint(host);
        assertThat(new PinnedHostKeyVerifier("dev-1", "SHA256:" + md5)
                .verify("dev-1.mesh", 22, host)).isFalse();
    }

    /** ...and an "MD5:"-labelled pin holding the SHA-256 base64 must not be honoured either. */
    @Test
    void rejects_md5LabelledPinHoldingTheSha256Digest() throws Exception {
        PublicKey host = rsaKey();
        String digest = openSshSha256Fp(host).substring("SHA256:".length());
        assertThat(new PinnedHostKeyVerifier("dev-1", "MD5:" + digest)
                .verify("dev-1.mesh", 22, host)).isFalse();
    }

    /** An UNLABELLED SHA-256 digest still matches (the seeding PR may have stored the bare form),
     *  and still exactly. */
    @Test
    void accepts_unlabelledSha256Digest_exactCaseOnly() throws Exception {
        PublicKey host = rsaKey();
        String digest = openSshSha256Fp(host).substring("SHA256:".length());
        assertThat(new PinnedHostKeyVerifier("dev-1", digest).verify("dev-1.mesh", 22, host)).isTrue();
        assertThat(new PinnedHostKeyVerifier("dev-1", digest.toLowerCase(java.util.Locale.ROOT))
                .verify("dev-1.mesh", 22, host)).isFalse();
    }

    @Test
    void findExistingAlgorithms_isEmpty_noKnownHostsConsulted() {
        PinnedHostKeyVerifier verifier = new PinnedHostKeyVerifier("dev-1", "aa:bb");
        assertThat(verifier.findExistingAlgorithms("dev-1.mesh", 22)).isEmpty();
    }
}
