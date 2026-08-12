package net.hugmesh.adminbff.sshissue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The SSH key-material crypto — the load-bearing FINGERPRINT-FORMAT EQUIVALENCE the whole
 * Option-B mechanism depends on: the BFF's {@code SHA256:...} fingerprint MUST equal the form
 * the node's {@code AuthorizedKeysCommand} computes from the offered key (the {@code %f}) and
 * pins via {@code device_ssh_license.key_fingerprints}. A mismatch is a silently-dead
 * credential (issued + licensed but never authorized), so this is tested directly.
 *
 * <ul>
 *   <li>SELF-CONSISTENT: the fingerprint == {@code SHA256: + base64-nopad(SHA-256(public wire
 *       bytes))} recomputed independently from the emitted public line.</li>
 *   <li>EXTERNAL EQUIVALENCE (when {@code ssh-keygen} is present): writing the public line and
 *       the private PEM to disk, {@code ssh-keygen -lf} of EITHER yields the SAME fingerprint,
 *       and {@code ssh-keygen -y} of the private PEM re-derives the SAME public line — proving
 *       the issued public key + the streamed private key + the pinned fingerprint are one
 *       coherent credential.</li>
 * </ul>
 */
class Ed25519KeyMaterialTest {

    @Test
    void fingerprint_isSha256OfPublicWireBytes_selfConsistent() throws Exception {
        Ed25519KeyMaterial m = Ed25519KeyMaterial.generate();

        assertThat(m.keyType()).isEqualTo("ssh-ed25519");
        assertThat(m.fingerprint()).startsWith("SHA256:");
        assertThat(m.publicOpenSshLine()).startsWith("ssh-ed25519 ");

        // Independently recompute the SHA256 fp from the emitted public line's key bytes.
        byte[] wire = Ed25519KeyMaterial.decodePublicWire(m.publicOpenSshLine());
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(wire);
        String expected = "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest);
        assertThat(m.fingerprint()).isEqualTo(expected);
    }

    @Test
    void privatePem_isOpenSshFormat_andNotEmpty() {
        Ed25519KeyMaterial m = Ed25519KeyMaterial.generate();
        String pem = m.privateOpenSshPemString();
        assertThat(pem).startsWith("-----BEGIN OPENSSH PRIVATE KEY-----");
        assertThat(pem).contains("-----END OPENSSH PRIVATE KEY-----");
        // privateKeyBytes() is a wipeable COPY; equal content, distinct array.
        assertThat(new String(m.privateKeyBytes())).isEqualTo(pem);
    }

    @Test
    void wipe_zeroesTheHeldPem() {
        Ed25519KeyMaterial m = Ed25519KeyMaterial.generate();
        m.wipe();
        // after wipe the held PEM is all NULs -> the string is NUL-filled, no PEM header.
        assertThat(m.privateOpenSshPemString()).doesNotContain("OPENSSH PRIVATE KEY");
    }

    static boolean sshKeygenPresent() {
        try {
            Process p = new ProcessBuilder("ssh-keygen", "-?").redirectErrorStream(true).start();
            p.waitFor();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * EXTERNAL EQUIVALENCE — the guard against a silently-dead credential: the BFF fingerprint
     * MUST equal {@code ssh-keygen -lf} of the public line AND of the private PEM, and
     * {@code ssh-keygen -y} of the private PEM MUST re-derive the issued public line (the node's
     * %f is exactly {@code ssh-keygen -lf} of the offered key).
     */
    @Test
    @EnabledIf("sshKeygenPresent")
    void fingerprint_equalsSshKeygen_andPrivateDerivesPublic() throws Exception {
        Ed25519KeyMaterial m = Ed25519KeyMaterial.generate();
        Path dir = Files.createTempDirectory("ssh-issue-fp");
        try {
            Path pub = dir.resolve("k.pub");
            Path priv = dir.resolve("id_test");
            Files.writeString(pub, m.publicOpenSshLine() + " issued\n");
            Files.writeString(priv, m.privateOpenSshPemString());
            priv.toFile().setReadable(false, false);
            priv.toFile().setReadable(true, true);
            priv.toFile().setWritable(false, false);
            priv.toFile().setWritable(true, true);

            String fpFromPub = keygenFingerprint(pub);
            String fpFromPriv = keygenFingerprint(priv);
            assertThat(fpFromPub).isEqualTo(m.fingerprint());
            assertThat(fpFromPriv).isEqualTo(m.fingerprint());

            // ssh-keygen -y derives the public key from the private PEM -> must match the issued line.
            String derivedPub = run(dir, "ssh-keygen", "-y", "-f", priv.toString()).trim();
            // ssh-keygen -y emits "ssh-ed25519 <base64>" (no comment) — compare the first two fields.
            assertThat(twoFields(derivedPub)).isEqualTo(twoFields(m.publicOpenSshLine()));
        } finally {
            try (var s = Files.walk(dir)) {
                s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static String keygenFingerprint(Path keyFile) throws Exception {
        // `ssh-keygen -lf <file>` -> "256 SHA256:.... comment (ED25519)"
        String out = run(keyFile.getParent(), "ssh-keygen", "-lf", keyFile.toString());
        for (String tok : out.trim().split("\\s+")) {
            if (tok.startsWith("SHA256:")) return tok;
        }
        throw new IllegalStateException("no SHA256 token in: " + out);
    }

    private static String twoFields(String openSshLine) {
        String[] p = openSshLine.trim().split("\\s+");
        return p[0] + " " + p[1];
    }

    private static String run(Path cwd, String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).directory(cwd.toFile()).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        p.waitFor();
        return out;
    }
}
