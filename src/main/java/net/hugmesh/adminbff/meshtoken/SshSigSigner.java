package net.hugmesh.adminbff.meshtoken;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

/**
 * OpenSSH {@code SSHSIG} signatures, Ed25519 only, with the JDK's own crypto: the exact armored
 * text {@code ssh-keygen -Y sign -n <namespace>} writes (PROTOCOL.sshsig).
 *
 * <p>Ed25519 is deterministic, so for the same key, namespace and message this produces the
 * SAME bytes as ssh-keygen. {@code MeshTokenGoldenTest} holds that against a committed
 * ssh-keygen signature, and the cross-check test runs {@code ssh-keygen -Y verify} on our output.
 *
 * <pre>
 *  signed data = "SSHSIG" || string(namespace) || string("") || string("sha512")
 *                || string(SHA-512(message))
 *  blob        = "SSHSIG" || uint32(1) || string(pubkey wire blob) || string(namespace)
 *                || string("") || string("sha512")
 *                || string(string("ssh-ed25519") || string(64-byte signature))
 *  armor       = "-----BEGIN SSH SIGNATURE-----\n" + base64(blob) in 70-column lines
 *                + "\n-----END SSH SIGNATURE-----\n"
 * </pre>
 */
public final class SshSigSigner {

    /** The namespace a HugMesh token is signed in. A signature for git or a file does not verify as a token. */
    public static final String NAMESPACE = "hugmesh-mesh-token@hugmesh.org";

    static final String HASH = "sha512";
    private static final byte[] MAGIC = "SSHSIG".getBytes(StandardCharsets.US_ASCII);
    private static final int ARMOR_COLUMNS = 70;

    private SshSigSigner() {
    }

    /**
     * Sign {@code message} in {@code namespace} with an Ed25519 key whose SSH public wire blob is
     * {@code publicWireBlob}; returns the armored signature as US-ASCII bytes (what ssh-keygen
     * writes to {@code <file>.sig}).
     */
    public static byte[] sign(byte[] message, String namespace, PrivateKey privateKey, byte[] publicWireBlob) {
        try {
            byte[] ns = namespace.getBytes(StandardCharsets.US_ASCII);
            byte[] digest = MessageDigest.getInstance("SHA-512").digest(message);

            ByteArrayOutputStream tbs = new ByteArrayOutputStream();
            DataOutputStream t = new DataOutputStream(tbs);
            t.write(MAGIC);
            string(t, ns);
            string(t, new byte[0]);
            string(t, HASH.getBytes(StandardCharsets.US_ASCII));
            string(t, digest);

            Signature s = Signature.getInstance("Ed25519");
            s.initSign(privateKey);
            s.update(tbs.toByteArray());
            byte[] raw = s.sign();

            ByteArrayOutputStream sigBlob = new ByteArrayOutputStream();
            DataOutputStream sg = new DataOutputStream(sigBlob);
            string(sg, "ssh-ed25519".getBytes(StandardCharsets.US_ASCII));
            string(sg, raw);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            DataOutputStream o = new DataOutputStream(out);
            o.write(MAGIC);
            o.writeInt(1);
            string(o, publicWireBlob);
            string(o, ns);
            string(o, new byte[0]);
            string(o, HASH.getBytes(StandardCharsets.US_ASCII));
            string(o, sigBlob.toByteArray());

            return armor(out.toByteArray()).getBytes(StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 SSHSIG signing failed", e);
        }
    }

    static String armor(byte[] blob) {
        String b64 = Base64.getEncoder().encodeToString(blob);
        StringBuilder sb = new StringBuilder("-----BEGIN SSH SIGNATURE-----\n");
        for (int i = 0; i < b64.length(); i += ARMOR_COLUMNS) {
            sb.append(b64, i, Math.min(b64.length(), i + ARMOR_COLUMNS)).append('\n');
        }
        return sb.append("-----END SSH SIGNATURE-----\n").toString();
    }

    private static void string(DataOutputStream o, byte[] b) throws IOException {
        o.writeInt(b.length);
        o.write(b);
    }
}
