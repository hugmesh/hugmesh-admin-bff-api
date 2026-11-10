package net.hugmesh.adminbff.meshtoken;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * BYTE-FOR-BYTE agreement with the Studio's reference implementation, held against committed
 * fixtures that the reference tools produced (see {@code src/test/resources/meshtoken/README.txt}):
 * <ul>
 *   <li>the canonical payload equals Python's {@code json.dumps(sort_keys, separators,
 *       ensure_ascii)} output for the same grant;</li>
 *   <li>the SSHSIG equals what {@code ssh-keygen -Y sign} wrote for the same key and payload
 *       (Ed25519 is deterministic, so equality is the right assertion, not "it verifies");</li>
 *   <li>the whole token equals the string {@code mesh_token.issue()} assembles.</li>
 * </ul>
 */
class MeshTokenGoldenTest {

    @Test
    void publicLineAndFingerprint_matchSshKeygen() {
        MeshTokenIssuerKey key = MeshTokenFixtures.key();
        assertThat(key.publicLine()).isEqualTo(MeshTokenFixtures.publicLine());
        assertThat(key.fingerprint()).isEqualTo(MeshTokenFixtures.FINGERPRINT);
        assertThat(key.toString()).isEqualTo("MeshTokenIssuerKey[" + MeshTokenFixtures.FINGERPRINT + "]");
    }

    @Test
    void canonicalPayload_equalsPythonJsonDumpsBytes() {
        assertThat(MeshTokenFixtures.goldenPayload().canonicalBytes())
                .isEqualTo(MeshTokenFixtures.bytes("golden-payload"));
    }

    @Test
    void canonicalPayload_minimalGrant_equalsPythonBytes() {
        MeshTokenPayload p = new MeshTokenPayload("hskey-AbC_123.xyz~", "example.org", 1577923200L, "",
                1577836800L, MeshTokenFixtures.publicLine(), "https://example.org", "m0", "", "user", false);
        assertThat(p.canonicalBytes()).isEqualTo(MeshTokenFixtures.bytes("golden-payload-minimal"));
    }

    @Test
    void canonicalPayload_hasExactlyTheTwelveKeysInSortedOrder() {
        String json = new String(MeshTokenFixtures.goldenPayload().canonicalBytes(), StandardCharsets.US_ASCII);
        int at = 0;
        for (String k : MeshTokenPayload.KEYS) {
            int i = json.indexOf("\"" + k + "\":", at);
            assertThat(i).as("key %s after offset %d", k, at).isGreaterThanOrEqualTo(at);
            at = i + 1;
        }
        assertThat(MeshTokenPayload.KEYS).hasSize(12).isSorted();
        assertThat(json.chars().filter(c -> c == ':').count())
                .as("12 keys, and no ':' inside any value of the golden grant except the login server port")
                .isEqualTo(12 + 1 + 1);
    }

    @Test
    void sshsig_equalsSshKeygenSignatureByteForByte() {
        byte[] sig = MeshTokenFixtures.key().sign(MeshTokenFixtures.bytes("golden-payload"));
        assertThat(new String(sig, StandardCharsets.US_ASCII))
                .isEqualTo(MeshTokenFixtures.text("golden-payload.sig"));
    }

    @Test
    void token_equalsTheReferenceTokenString() {
        MeshTokenPayload p = MeshTokenFixtures.goldenPayload();
        byte[] body = p.canonicalBytes();
        String token = MeshTokenPayload.FORMAT + "." + MeshTokenService.b64u(body) + "."
                + MeshTokenService.b64u(MeshTokenFixtures.key().sign(body));
        assertThat(token).isEqualTo(MeshTokenFixtures.text("golden-token.txt").trim());
        assertThat(token).doesNotContain("=");
    }

    @Test
    void armor_wrapsAt70ColumnsLikeSshKeygen() {
        String sig = MeshTokenFixtures.text("golden-payload.sig");
        String[] lines = sig.split("\n");
        assertThat(lines[0]).isEqualTo("-----BEGIN SSH SIGNATURE-----");
        assertThat(lines[lines.length - 1]).isEqualTo("-----END SSH SIGNATURE-----");
        for (int i = 1; i < lines.length - 2; i++) {
            assertThat(lines[i]).hasSize(70);
        }
        assertThat(SshSigSigner.armor(Base64.getDecoder().decode(String.join("",
                java.util.Arrays.copyOfRange(lines, 1, lines.length - 1))))).isEqualTo(sig);
    }

    @Test
    void jsonEscaping_matchesPythonEnsureAscii() {
        // Python 3: json.dumps("a\"b\\c\n\r\t\b\f\x01\x1f\x7f \xe9\U0001F600~/", ensure_ascii=True)
        String in = "a\"b\\c\n\r\t\b\f\u0001\u001f\u007f é😀~/";
        StringBuilder b = new StringBuilder();
        MeshTokenPayload.appendJsonString(b, in);
        assertThat(b.toString()).isEqualTo("\"a\\\"b\\\\c\\n\\r\\t\\b\\f\\u0001\\u001f\\u007f \\u00e9\\ud83d\\ude00~/\"");
    }

    // ── the two key-file formats load to the SAME key ─────────────────────────────────

    @Test
    void openSshKeyFile_loadsToTheGoldenKey(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("issuer");
        Files.writeString(f, MeshTokenFixtures.openSshPem(), StandardCharsets.US_ASCII);
        MeshTokenIssuerKey k = MeshTokenIssuerKey.load(f);
        assertThat(k.fingerprint()).isEqualTo(MeshTokenFixtures.FINGERPRINT);
        assertThat(new String(k.sign(MeshTokenFixtures.bytes("golden-payload")), StandardCharsets.US_ASCII))
                .isEqualTo(MeshTokenFixtures.text("golden-payload.sig"));
    }

    @Test
    void pkcs8KeyFile_loadsToTheGoldenKey(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("issuer.pem");
        Files.writeString(f, MeshTokenFixtures.pkcs8Pem(), StandardCharsets.US_ASCII);
        assertThat(MeshTokenIssuerKey.load(f).fingerprint()).isEqualTo(MeshTokenFixtures.FINGERPRINT);
    }

    @Test
    void sshKeygenWrittenKeyFile_loads(@TempDir Path dir) throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(SshKeygen.available(), "ssh-keygen not installed");
        Path f = dir.resolve("k");
        SshKeygen.run(dir, null, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", f.toString());
        String pub = Files.readString(dir.resolve("k.pub")).trim();
        MeshTokenIssuerKey k = MeshTokenIssuerKey.load(f);
        assertThat(k.publicLine()).isEqualTo(pub);
        assertThat(k.fingerprint()).isEqualTo(SshKeygen.fingerprint(dir.resolve("k.pub")));
    }

    @Test
    void passphraseProtectedKey_isRefusedWithASentence(@TempDir Path dir) throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(SshKeygen.available(), "ssh-keygen not installed");
        Path f = dir.resolve("k");
        SshKeygen.run(dir, null, "-q", "-t", "ed25519", "-N", "correct horse", "-C", "", "-f", f.toString());
        assertThatThrownBy(() -> MeshTokenIssuerKey.load(f))
                .isInstanceOf(MeshTokenIssuerKey.IssuerKeyException.class)
                .hasMessageContaining("passphrase-protected");
    }

    @Test
    void missingOrForeignKeyFile_isRefusedWithoutKeyBytesInTheMessage(@TempDir Path dir) throws Exception {
        assertThatThrownBy(() -> MeshTokenIssuerKey.load(dir.resolve("absent")))
                .isInstanceOf(MeshTokenIssuerKey.IssuerKeyException.class)
                .hasMessageContaining("cannot be read");
        Path rsa = dir.resolve("rsa");
        Files.writeString(rsa, MeshTokenFixtures.pem("RSA PRIVATE KEY", new byte[] {1, 2, 3}));
        assertThatThrownBy(() -> MeshTokenIssuerKey.load(rsa))
                .isInstanceOf(MeshTokenIssuerKey.IssuerKeyException.class)
                .hasMessageContaining("Ed25519");
    }
}
