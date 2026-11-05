package net.hugmesh.adminbff.meshtoken;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Runs the real OpenSSH {@code ssh-keygen} for the cross-checks (tests skip when it is absent). */
final class SshKeygen {

    private SshKeygen() {
    }

    static boolean available() {
        try {
            Process p = new ProcessBuilder("ssh-keygen", "-?").redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor(10, TimeUnit.SECONDS);
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** Run ssh-keygen in {@code dir} with {@code stdin}; returns exit code, output in {@link #lastOutput}. */
    static int run(Path dir, byte[] stdin, String... args) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        cmd.add("ssh-keygen");
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        if (stdin != null) {
            p.getOutputStream().write(stdin);
        }
        p.getOutputStream().close();
        lastOutput = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!p.waitFor(30, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            return -1;
        }
        return p.exitValue();
    }

    static String lastOutput = "";

    /** The {@code SHA256:...} field of {@code ssh-keygen -lf}. */
    static String fingerprint(Path pub) throws IOException, InterruptedException {
        int rc = run(pub.getParent(), null, "-lf", pub.toString());
        if (rc != 0) {
            throw new IllegalStateException("ssh-keygen -lf failed: " + lastOutput);
        }
        return lastOutput.trim().split(" ")[1];
    }

    /**
     * {@code ssh-keygen -Y verify} of {@code sig} over {@code payload} for {@code issuerLine} in
     * the token namespace — exactly the tray's {@code _check_signature}.
     */
    static int verify(Path dir, String issuerLine, byte[] payload, byte[] sig) throws IOException, InterruptedException {
        Path signers = dir.resolve("allowed_signers");
        Files.writeString(signers, "issuer namespaces=\"" + SshSigSigner.NAMESPACE + "\" " + issuerLine + "\n",
                StandardCharsets.US_ASCII);
        Path s = dir.resolve("payload.sig");
        Files.write(s, sig);
        return run(dir, payload, "-Y", "verify", "-f", signers.toString(), "-I", "issuer",
                "-n", SshSigSigner.NAMESPACE, "-s", s.toString());
    }
}
