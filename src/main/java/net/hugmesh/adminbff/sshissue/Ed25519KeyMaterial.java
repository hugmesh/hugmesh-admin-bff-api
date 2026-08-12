package net.hugmesh.adminbff.sshissue;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.util.Base64;

/**
 * In-memory Ed25519 SSH key material for admin SSH key-ISSUANCE (SSH PR-4, Option B). Mints a
 * keypair and derives the THREE artefacts the issuance leg needs — all NON-SECRET except the
 * private PEM, which is held only transiently and never logged/persisted:
 *
 * <ul>
 *   <li>the SHA256 {@link #fingerprint()} — the EXACT {@code %f} form the node's
 *       {@code AuthorizedKeysCommand} computes from the OFFERED key and matches against
 *       {@code device_ssh_license.key_fingerprints}. This is {@code "SHA256:" +
 *       base64-nopad(SHA-256(ssh-wire-format-public-key))}, byte-identical to
 *       {@code ssh-keygen -lf} and the node's {@code %f} — the FINGERPRINT-FORMAT EQUIVALENCE
 *       the export depends on (a mismatch is a silently-dead credential).</li>
 *   <li>the NON-SECRET {@link #publicOpenSshLine()} — {@code "ssh-ed25519 AAAA..."} stored on
 *       the audit row;</li>
 *   <li>the {@link #privateOpenSshPem()} — the {@code -----BEGIN OPENSSH PRIVATE KEY-----} PEM
 *       streamed ONCE to the operator, then dropped.</li>
 * </ul>
 *
 * <p><b>Why not {@code SecurityUtils.getFingerprint}.</b> sshj's
 * {@code SecurityUtils.getFingerprint(PublicKey)} returns the LEGACY MD5 colon-hex form
 * ({@code 99:89:...}), NOT the {@code SHA256:...} form the node pins. Using it would mint a
 * credential whose fingerprint never matches the node's {@code %f} — a silently-dead key. We
 * therefore compute the SHA256 form directly over the sshj wire-encoded public key (the same
 * bytes {@code ssh-keygen} hashes). The {@code Ed25519KeyMaterialTest} pins this equivalence.
 */
public final class Ed25519KeyMaterial {

    private final KeyType keyType;
    private final String fingerprint;
    private final String publicOpenSshLine;
    private final char[] privateOpenSshPem;

    private Ed25519KeyMaterial(KeyType keyType, String fingerprint, String publicOpenSshLine,
                               char[] privateOpenSshPem) {
        this.keyType = keyType;
        this.fingerprint = fingerprint;
        this.publicOpenSshLine = publicOpenSshLine;
        this.privateOpenSshPem = privateOpenSshPem;
    }

    /** Mint a fresh Ed25519 keypair and derive all artefacts. The private key bytes live only in
     *  the returned PEM (and the transient generator state, which is GC'd). */
    public static Ed25519KeyMaterial generate() {
        try {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            PublicKey pub = kp.getPublic();
            KeyType kt = KeyType.fromKey(pub);
            byte[] wire = pubKeyWireBytes(pub, kt);
            String fp = sha256Fingerprint(wire);
            String pubLine = kt.toString() + " " + Base64.getEncoder().encodeToString(wire);

            EdECPrivateKey sk = (EdECPrivateKey) kp.getPrivate();
            byte[] seed = sk.getBytes().orElseThrow(() -> new IllegalStateException(
                    "Ed25519 private key seed unavailable"));
            char[] pem = openSshPrivatePem(seed);
            // best-effort wipe of the intermediate seed
            java.util.Arrays.fill(seed, (byte) 0);
            return new Ed25519KeyMaterial(kt, fp, pubLine, pem);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("failed to mint Ed25519 SSH key material", e);
        }
    }

    /** The SSH-key-algorithm token ({@code ssh-ed25519}). */
    public String keyType() {
        return keyType.toString();
    }

    /** The {@code SHA256:...} fingerprint — the {@code %f} the node pins. NON-SECRET. */
    public String fingerprint() {
        return fingerprint;
    }

    /** The NON-SECRET OpenSSH public line ({@code ssh-ed25519 AAAA...}). */
    public String publicOpenSshLine() {
        return publicOpenSshLine;
    }

    /** The OpenSSH private-key PEM as UTF-8 bytes — the SECRET, streamed ONCE then wiped by the
     *  caller's {@code doFinally}. A fresh array each call (the internal char[] is copied). */
    public byte[] privateKeyBytes() {
        // Encode the char[] PEM to UTF-8 without an intermediate String (which would be
        // immutable + un-wipeable). ASCII-only PEM, so a 1:1 char->byte holds for the body.
        byte[] out = new byte[privateOpenSshPem.length];
        for (int i = 0; i < privateOpenSshPem.length; i++) {
            out[i] = (byte) privateOpenSshPem[i];
        }
        return out;
    }

    /** The PEM as a String — TEST-ONLY convenience for the round-trip assertion (production
     *  streams {@link #privateKeyBytes()} so the secret is a wipeable array). */
    String privateOpenSshPemString() {
        return new String(privateOpenSshPem);
    }

    /** Best-effort wipe of the held private PEM (called after the single-use download). */
    public void wipe() {
        java.util.Arrays.fill(privateOpenSshPem, '\0');
    }

    // ── derivation ─────────────────────────────────────────────────────────────────

    private static byte[] pubKeyWireBytes(PublicKey pub, KeyType kt) {
        Buffer.PlainBuffer buf = new Buffer.PlainBuffer();
        kt.putPubKeyIntoBuffer(pub, buf);
        return buf.getCompactData();
    }

    /** {@code "SHA256:" + base64-nopad(SHA-256(wire))} — byte-identical to ssh-keygen -lf / %f. */
    static String sha256Fingerprint(byte[] pubKeyWireBytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(pubKeyWireBytes);
        return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest);
    }

    private static char[] openSshPrivatePem(byte[] ed25519Seed) throws Exception {
        Ed25519PrivateKeyParameters params = new Ed25519PrivateKeyParameters(ed25519Seed, 0);
        byte[] openssh = OpenSSHPrivateKeyUtil.encodePrivateKey(params);
        StringWriter sw = new StringWriter();
        try (PemWriter pw = new PemWriter(sw)) {
            pw.writeObject(new PemObject("OPENSSH PRIVATE KEY", openssh));
        }
        // params holds a copy of the seed; there is no public clear() — it is GC'd. The body
        // bytes are the secret; the PEM char[] is the canonical secret carrier from here on.
        return sw.toString().toCharArray();
    }

    /** TEST-ONLY: compute the SHA256 fingerprint of an OpenSSH public line's key bytes — used by
     *  the equivalence test to cross-check against ssh-keygen without re-deriving by hand. */
    static byte[] decodePublicWire(String openSshLine) {
        String[] parts = openSshLine.trim().split("\\s+");
        return Base64.getDecoder().decode(parts[1].getBytes(StandardCharsets.US_ASCII));
    }
}
