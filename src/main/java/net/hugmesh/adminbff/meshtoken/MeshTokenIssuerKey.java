package net.hugmesh.adminbff.meshtoken;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * The mesh's token-issuer key: an Ed25519 private key that NEVER leaves this process, plus the
 * public artefacts derived from it (the {@code ssh-ed25519 <base64>} line that goes into every
 * token's {@code issuer} field, and its {@code SHA256:} fingerprint as {@code ssh-keygen -lf}
 * prints it, which the trays compare out of band).
 *
 * <h2>Formats</h2>
 * <ul>
 *   <li>OpenSSH ({@code -----BEGIN OPENSSH PRIVATE KEY-----}, what
 *       {@code ssh-keygen -t ed25519 -N ''} writes) — the local stack's and Vault's format.
 *       Parsed with BouncyCastle's {@code OpenSSHPrivateKeyUtil}, the parser this BFF's
 *       {@code sshissue.Ed25519KeyMaterial} already uses for the same format (sshj's key-file
 *       reader yields a non-JDK key type, and the JDK signer needs an {@code EdECPrivateKey}).
 *       A passphrase-protected key is refused: the server has nobody to type it.</li>
 *   <li>PKCS#8 ({@code -----BEGIN PRIVATE KEY-----}) as a fallback, the
 *       {@code app.registry.signing-key-path} precedent.</li>
 * </ul>
 *
 * <p>{@link #toString()} prints the fingerprint only. Nothing in this class logs.
 */
public final class MeshTokenIssuerKey {

    private static final String KEY_TYPE = "ssh-ed25519";

    private final PrivateKey privateKey;
    private final byte[] publicWireBlob;
    private final String publicLine;
    private final String fingerprint;

    private MeshTokenIssuerKey(PrivateKey privateKey, byte[] publicKeyRaw) {
        this.privateKey = privateKey;
        this.publicWireBlob = wireBlob(publicKeyRaw);
        this.publicLine = KEY_TYPE + " " + Base64.getEncoder().encodeToString(publicWireBlob);
        this.fingerprint = fingerprintOf(publicWireBlob);
    }

    /** Thrown when the key file cannot be used; the message names the path and the reason, never key bytes. */
    public static final class IssuerKeyException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public IssuerKeyException(String message) {
            super(message);
        }
    }

    /** Load the issuer key from {@code path} (OpenSSH, else PKCS#8 PEM). */
    public static MeshTokenIssuerKey load(Path path) {
        String text;
        try {
            text = Files.readString(path, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new IssuerKeyException("The mesh-token issuer key " + path + " cannot be read ("
                    + e.getClass().getSimpleName() + ").");
        }
        try (PemReader r = new PemReader(new StringReader(text))) {
            PemObject pem = r.readPemObject();
            if (pem == null) {
                throw new IssuerKeyException("The mesh-token issuer key " + path + " is not a PEM key file.");
            }
            return switch (pem.getType()) {
                case "OPENSSH PRIVATE KEY" -> fromOpenSsh(pem.getContent(), path);
                case "PRIVATE KEY" -> fromPkcs8(pem.getContent(), path);
                default -> throw new IssuerKeyException("The mesh-token issuer key " + path
                        + " is a " + pem.getType() + "; an Ed25519 OpenSSH or PKCS#8 key is required.");
            };
        } catch (IOException e) {
            throw new IssuerKeyException("The mesh-token issuer key " + path + " is not a PEM key file.");
        }
    }

    /** Build from a raw 32-byte Ed25519 seed (tests, and the two loaders). */
    public static MeshTokenIssuerKey fromSeed(byte[] seed) {
        if (seed == null || seed.length != Ed25519PrivateKeyParameters.KEY_SIZE) {
            throw new IssuerKeyException("An Ed25519 seed is exactly 32 bytes.");
        }
        try {
            Ed25519PrivateKeyParameters bc = new Ed25519PrivateKeyParameters(seed, 0);
            byte[] pub = bc.generatePublicKey().getEncoded();
            PrivateKey jdk = KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed.clone()));
            return new MeshTokenIssuerKey(jdk, pub);
        } catch (GeneralSecurityException e) {
            throw new IssuerKeyException("The JDK cannot build an Ed25519 key (" + e.getClass().getSimpleName() + ").");
        }
    }

    private static MeshTokenIssuerKey fromOpenSsh(byte[] blob, Path path) {
        if (!"none".equals(openSshCipher(blob))) {
            throw new IssuerKeyException("The mesh-token issuer key " + path + " is passphrase-protected; "
                    + "the server cannot unlock it. Generate it with ssh-keygen -t ed25519 -N ''.");
        }
        AsymmetricKeyParameter p;
        try {
            p = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob);
        } catch (RuntimeException e) {
            throw new IssuerKeyException("The mesh-token issuer key " + path + " is not a readable OpenSSH key.");
        }
        if (!(p instanceof Ed25519PrivateKeyParameters ed)) {
            throw new IssuerKeyException("The mesh-token issuer key " + path + " is not an Ed25519 key.");
        }
        byte[] seed = ed.getEncoded();
        try {
            return fromSeed(seed);
        } finally {
            Arrays.fill(seed, (byte) 0);
        }
    }

    private static MeshTokenIssuerKey fromPkcs8(byte[] der, Path path) {
        try {
            PrivateKey k = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
            byte[] seed = ((EdECPrivateKey) k).getBytes().orElseThrow(
                    () -> new IssuerKeyException("The mesh-token issuer key " + path + " carries no Ed25519 seed."));
            try {
                return fromSeed(seed);
            } finally {
                Arrays.fill(seed, (byte) 0);
            }
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new IssuerKeyException("The mesh-token issuer key " + path + " is not an Ed25519 PKCS#8 key.");
        }
    }

    /** The cipher name of an openssh-key-v1 blob ("none" for an unencrypted key), or "" if unreadable. */
    static String openSshCipher(byte[] blob) {
        byte[] magic = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);
        if (blob.length < magic.length + 4 || !Arrays.equals(Arrays.copyOf(blob, magic.length), magic)) {
            return "";
        }
        int o = magic.length;
        int n = ((blob[o] & 0xff) << 24) | ((blob[o + 1] & 0xff) << 16) | ((blob[o + 2] & 0xff) << 8) | (blob[o + 3] & 0xff);
        if (n < 0 || o + 4 + n > blob.length) {
            return "";
        }
        return new String(blob, o + 4, n, StandardCharsets.US_ASCII);
    }

    static byte[] wireBlob(byte[] publicKeyRaw) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream o = new DataOutputStream(bos);
            byte[] t = KEY_TYPE.getBytes(StandardCharsets.US_ASCII);
            o.writeInt(t.length);
            o.write(t);
            o.writeInt(publicKeyRaw.length);
            o.write(publicKeyRaw);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code "SHA256:" + unpadded base64(sha256(wire blob))} — what {@code ssh-keygen -lf} prints. */
    static String fingerprintOf(byte[] wireBlob) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(wireBlob);
            return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(d);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Sign canonical payload bytes in the token namespace; the armored SSHSIG text as bytes. */
    public byte[] sign(byte[] payload) {
        return SshSigSigner.sign(payload, SshSigSigner.NAMESPACE, privateKey, publicWireBlob);
    }

    /** {@code ssh-ed25519 <base64>} with no comment — the token's {@code issuer} field. */
    public String publicLine() {
        return publicLine;
    }

    /** {@code SHA256:...} as {@code ssh-keygen -lf} prints it. */
    public String fingerprint() {
        return fingerprint;
    }

    @Override
    public String toString() {
        return "MeshTokenIssuerKey[" + fingerprint + "]";
    }
}
