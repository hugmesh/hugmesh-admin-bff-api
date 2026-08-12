package net.hugmesh.adminbff.device;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Detached Ed25519 signer for the device-registry export [FIX-SIGNCACHE]. The export is a
 * DETACHED SIGNATURE over the canonical body {@code {generation, mesh_id, content-hash,
 * body}} so each enforcement node (the per-node sshd {@code AuthorizedKeysCommand} and the
 * headscale policy generator) can VERIFY with the public half baked in via the key-USB and
 * fail-closed on an unsigned / tampered / rolled-back payload, keeping its last-good cache.
 *
 * <h3>SIGNING KEY (never in git)</h3>
 * The private half is loaded from config / a mounted secret — NEVER committed:
 * <ul>
 *   <li>{@code app.registry.signing-key} — base64 PKCS#8 Ed25519 private key (env/secret
 *       injected), OR</li>
 *   <li>{@code app.registry.signing-key-path} — a path to a mounted PKCS#8 key file.</li>
 * </ul>
 * When NEITHER is configured the signer is in a deliberate NO-KEY state: it cannot sign,
 * so {@link #sign(byte[])} fails closed and the export is served UNSIGNED (the consumer
 * fail-closes and keeps its last-good cache). The default {@code application.yml} embeds
 * NO key. Ed25519 is JDK-native (JDK 15+), so this adds no crypto dependency. Tests
 * generate an ephemeral key via {@link #ephemeral()}.
 */
@Component
public class RegistrySigner {

    private static final Logger log = LoggerFactory.getLogger(RegistrySigner.class);

    /** JDK-native Ed25519 (no BouncyCastle). */
    public static final String ALG = "Ed25519";

    /** The private signing half (null when no key is configured — fail-closed). */
    private final PrivateKey privateKey;
    /** The public verifying half (for {@link #publicKeyBase64()} export + self-verify). */
    private final PublicKey publicKey;

    // The package-private RegistrySigner(KeyPair) test seam makes this a multi-constructor
    // bean, so Spring no longer auto-selects the injection constructor — mark it explicitly
    // (the constructor the container already uses in prod). Behaviorally inert.
    @Autowired
    public RegistrySigner(
            @Value("${app.registry.signing-key:}") String signingKeyBase64,
            @Value("${app.registry.signing-key-path:}") String signingKeyPath,
            @Value("${app.registry.public-key:}") String publicKeyBase64) {
        this.privateKey = loadPrivate(signingKeyBase64, signingKeyPath);
        this.publicKey = loadPublic(publicKeyBase64);
        if (privateKey == null) {
            log.warn("[registry-signer] NO signing key configured (app.registry.signing-key[-path] unset) — "
                    + "the device-registry export will be served UNSIGNED and consumers must fail closed");
        }
    }

    /** Direct-keypair constructor for tests (ephemeral, never committed). */
    RegistrySigner(KeyPair keyPair) {
        this.privateKey = keyPair == null ? null : keyPair.getPrivate();
        this.publicKey = keyPair == null ? null : keyPair.getPublic();
    }

    /** True iff a signing key is present (so the export can be signed). */
    public boolean canSign() {
        return privateKey != null;
    }

    /**
     * Detached Ed25519 signature over {@code body} (base64). Returns {@code null} when no
     * signing key is configured (fail-closed — the export is served unsigned).
     */
    public String sign(byte[] body) {
        if (privateKey == null) return null;
        try {
            Signature sig = Signature.getInstance(ALG);
            sig.initSign(privateKey);
            sig.update(body);
            return Base64.getEncoder().encodeToString(sig.sign());
        } catch (Exception e) {
            log.error("[registry-signer] signing failed (export served unsigned): {}", e.toString());
            return null;
        }
    }

    /**
     * Verify a detached base64 signature over {@code body} against the given base64 X.509
     * (SubjectPublicKeyInfo) Ed25519 public key. This is the SAME check a node performs
     * with the baked public half; exposed so tests + an in-process consumer fail-close
     * identically (false on any error). A node ALSO checks the generation monotonicity
     * (rollback guard) — that is the consumer's responsibility, modelled in the tests.
     */
    public static boolean verify(byte[] body, String signatureBase64, String publicKeyBase64) {
        if (body == null || signatureBase64 == null || publicKeyBase64 == null) return false;
        try {
            byte[] pub = Base64.getDecoder().decode(publicKeyBase64);
            PublicKey key = KeyFactory.getInstance(ALG).generatePublic(new X509EncodedKeySpec(pub));
            Signature sig = Signature.getInstance(ALG);
            sig.initVerify(key);
            sig.update(body);
            return sig.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (Exception e) {
            return false;   // fail-closed on malformed key / signature / body
        }
    }

    /** The public verifying half (base64 X.509 SubjectPublicKeyInfo) the node bakes in to
     *  verify, or {@code null} when no key is configured. */
    public String publicKeyBase64() {
        return publicKey == null ? null : Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /** SHA-256 content hash (base64) of {@code body} — the {@code content-hash} field of
     *  the signed envelope (a fast integrity pre-check the node can also recompute). */
    public static String contentHash(byte[] body) {
        try {
            return Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(body));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);   // never on a JDK
        }
    }

    /** Generate a fresh ephemeral Ed25519 keypair (TESTS ONLY — never persisted/committed). */
    public static KeyPair ephemeral() {
        try {
            return KeyPairGenerator.getInstance(ALG).generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Ed25519 keypair generation unavailable", e);
        }
    }

    // ── key loading (config base64 OR mounted file; never embedded) ─────────────

    /** Load the PRIVATE signing half from base64 PKCS#8 (preferred) or a mounted PEM/DER
     *  key file. Returns null (sign-disabled, fail-closed) when neither is configured. */
    private static PrivateKey loadPrivate(String base64, String path) {
        try {
            String pkcs8 = null;
            if (base64 != null && !base64.isBlank()) {
                pkcs8 = stripPem(base64);
            } else if (path != null && !path.isBlank()) {
                pkcs8 = stripPem(new String(Files.readAllBytes(Path.of(path.trim())), StandardCharsets.UTF_8));
            }
            if (pkcs8 == null || pkcs8.isEmpty()) return null;
            byte[] der = Base64.getDecoder().decode(pkcs8);
            return KeyFactory.getInstance(ALG).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            log.error("[registry-signer] failed to load signing key (serving unsigned): {}", e.toString());
            return null;
        }
    }

    /** Load the PUBLIC verifying half from base64 X.509 (SubjectPublicKeyInfo) — the same
     *  bytes baked into the node's key-USB so {@link #publicKeyBase64()} advertises the
     *  exact key consumers verify with. Null when unset (sign-only; the node uses its
     *  baked copy). */
    private static PublicKey loadPublic(String base64) {
        try {
            if (base64 == null || base64.isBlank()) return null;
            byte[] der = Base64.getDecoder().decode(stripPem(base64));
            return KeyFactory.getInstance(ALG).generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            log.error("[registry-signer] failed to load public key: {}", e.toString());
            return null;
        }
    }

    private static String stripPem(String s) {
        return s.replaceAll("-----BEGIN [A-Z0-9 ]+-----", "")
                .replaceAll("-----END [A-Z0-9 ]+-----", "")
                .replaceAll("\\s", "")
                .trim();
    }
}
