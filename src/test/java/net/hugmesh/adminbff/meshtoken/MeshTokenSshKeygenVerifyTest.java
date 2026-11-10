package net.hugmesh.adminbff.meshtoken;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A token issued by {@link MeshTokenService} (fresh key, real clock) verifies with the real
 * {@code ssh-keygen -Y verify -n hugmesh-mesh-token@hugmesh.org} — the exact call the Studio
 * tray makes — and a token whose payload was changed does not. Skipped where ssh-keygen is not
 * installed.
 *
 * <p>With {@code -Dmeshtoken.dump.dir=<dir>} it also writes {@code token.txt} and
 * {@code issuer.pub} there, so the Studio's Python verifier can be run on a BFF-issued token
 * ({@code python -m hugmesh_studio.core.mesh_token show}). The dumped token carries a fake
 * pre-auth key from a throwaway key generated for that run.
 */
class MeshTokenSshKeygenVerifyTest {

    MeshTokenService service;
    MeshTokenIssuerKey key;

    @BeforeEach
    void setUp(@TempDir Path dir) throws Exception {
        Assumptions.assumeTrue(SshKeygen.available(), "ssh-keygen not installed");
        assertThat(SshKeygen.run(dir, null, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f",
                dir.resolve("issuer").toString())).isZero();
        key = MeshTokenIssuerKey.load(dir.resolve("issuer"));
        HeadscalePreAuthKeyClient hs = mock(HeadscalePreAuthKeyClient.class);
        when(hs.create(any())).thenReturn(Mono.just(new HeadscalePreAuthKeyClient.PreAuthKey("3",
                "fakefakefakefake0123456789abcdef0123456789abcdef")));
        MeshTokenIssuedRowRepository repo = mock(MeshTokenIssuedRowRepository.class);
        when(repo.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        service = new MeshTokenService(MeshTokenServiceTest.props(true), hs, repo, Clock.systemUTC(), key);
    }

    @Test
    void bffIssuedToken_passesSshKeygenVerify_andATamperedOneFails(@TempDir Path dir) throws Exception {
        String token = service.issue("sub-1", PrincipalDomain.superadminFor("default"),
                new MeshTokenService.IssueRequest("hugmesh.net", "admin", true, 3600L, "verify-node")).block().token();
        String[] parts = token.split("\\.");
        byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        byte[] sig = Base64.getUrlDecoder().decode(parts[2]);

        int rc = SshKeygen.verify(dir, key.publicLine(), payload, sig);
        assertThat(rc).as("ssh-keygen -Y verify: %s", SshKeygen.lastOutput).isZero();
        assertThat(SshKeygen.lastOutput).contains("Good \"" + SshSigSigner.NAMESPACE + "\" signature");

        byte[] tampered = new String(payload, StandardCharsets.US_ASCII)
                .replace("\"role\":\"admin\"", "\"role\":\"superadmin\"").getBytes(StandardCharsets.US_ASCII);
        assertThat(tampered).isNotEqualTo(payload);
        assertThat(SshKeygen.verify(dir, key.publicLine(), tampered, sig)).isNotZero();

        // another namespace (e.g. git's) must not accept a token signature
        Path signers = dir.resolve("allowed_signers_git");
        Files.writeString(signers, "issuer namespaces=\"git\" " + key.publicLine() + "\n");
        Files.write(dir.resolve("s.sig"), sig);
        assertThat(SshKeygen.run(dir, payload, "-Y", "verify", "-f", signers.toString(), "-I", "issuer",
                "-n", "git", "-s", dir.resolve("s.sig").toString())).isNotZero();

        String dump = System.getProperty("meshtoken.dump.dir");
        if (dump != null && !dump.isBlank()) {
            Path d = Path.of(dump);
            Files.createDirectories(d);
            Files.writeString(d.resolve("token.txt"), token + "\n");
            Files.writeString(d.resolve("issuer.pub"), key.publicLine() + "\n");
        }
    }
}
