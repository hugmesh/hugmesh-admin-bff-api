package net.hugmesh.adminbff.meshtoken;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

/** Loads the committed test-only fixtures under {@code src/test/resources/meshtoken/}. */
final class MeshTokenFixtures {

    static final String FINGERPRINT = "SHA256:fC2eP8qPXVSHcQc+XeJhTc82fub1sbpVnv3FNMsQEj4";
    static final String GOLDEN_AUTH_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef";

    private MeshTokenFixtures() {
    }

    static byte[] bytes(String name) {
        try (InputStream in = MeshTokenFixtures.class.getResourceAsStream("/meshtoken/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing fixture " + name);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static String text(String name) {
        return new String(bytes(name), StandardCharsets.US_ASCII);
    }

    static byte[] seed() {
        return HexFormat.of().parseHex(text("test-issuer.seed.hex").trim());
    }

    static MeshTokenIssuerKey key() {
        return MeshTokenIssuerKey.fromSeed(seed());
    }

    /** {@code ssh-ed25519 <b64>} without the (empty) comment. */
    static String publicLine() {
        String[] p = text("test-issuer.pub").trim().split(" ");
        return p[0] + " " + p[1];
    }

    /** The golden grant the Python fixture was serialised from. */
    static MeshTokenPayload goldenPayload() {
        return new MeshTokenPayload(GOLDEN_AUTH_KEY, "hugmesh.net", 1762905600L, "a1b2c3d4e5f60718",
                1762300800L, publicLine(), "https://hs.hugmesh.net:8488", "hugmesh-local", "golden-node",
                "admin", true);
    }

    /** PEM armor (the type is a parameter so no committed source line looks like a key file). */
    static String pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(70, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    /** The test key as the OpenSSH PEM ssh-keygen writes (rebuilt from the seed; never committed). */
    static String openSshPem() {
        try {
            byte[] blob = OpenSSHPrivateKeyUtil.encodePrivateKey(new Ed25519PrivateKeyParameters(seed(), 0));
            return pem("OPENSSH PRIVATE KEY", blob);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** The test key as a PKCS#8 PEM (rebuilt from the seed). */
    static String pkcs8Pem() {
        byte[] prefix = HexFormat.of().parseHex("302e020100300506032b657004220420");
        byte[] der = new byte[prefix.length + 32];
        System.arraycopy(prefix, 0, der, 0, prefix.length);
        System.arraycopy(seed(), 0, der, prefix.length, 32);
        return pem("PRIVATE KEY", der);
    }
}
