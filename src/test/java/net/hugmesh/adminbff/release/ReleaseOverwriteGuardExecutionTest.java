package net.hugmesh.adminbff.release;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EXECUTES the release.yml step "Refuse to overwrite a published version" the way GitHub
 * Actions does, instead of reading it.
 *
 * <p>The step has no {@code shell:} key and the workflow has no {@code defaults:} block, so
 * Actions runs it as {@code bash -e {0}}. Its own {@code set -uo pipefail} does not turn
 * {@code -e} off. The old form {@code out=$(docker buildx imagetools inspect ...)} followed by
 * {@code rc=$?} therefore ended the step at the probe whenever the image did not exist yet
 * (the normal first publish): exit 1, no output, and the build never ran. A text check cannot
 * see that, so this test runs the step's {@code run:} block under {@code bash -e} with a stub
 * {@code docker} on the PATH:
 *
 * <ul>
 *   <li>absent ("not found") and denied: the step continues (exit 0, "is not published yet");</li>
 *   <li>present: the step refuses (exit 1, "already exists");</li>
 *   <li>any other error: the step fails closed (exit 1, "could not tell whether").</li>
 * </ul>
 *
 * <p>The stub writes a marker on every call, so a step that stops probing cannot pass. There
 * is deliberately no skip when bash is missing: a guard that skips itself reports green blind.
 */
class ReleaseOverwriteGuardExecutionTest {

    private static final Path ROOT = Path.of("").toAbsolutePath();
    private static final String STEP = "- name: Refuse to overwrite a published version";
    private static final String REF = "ghcr.io/hugmesh/hugmesh-admin-bff-api:0.0.1-beta.1";

    /** A docker stub that answers only "buildx imagetools inspect <ref>". */
    private static final String DOCKER_STUB = """
            #!/bin/sh
            if [ "$1 $2 $3" != "buildx imagetools inspect" ]; then
              echo "stub docker: unexpected call: $*"
              exit 99
            fi
            : > "${STUB_MARKER}"
            case "${STUB_MODE}" in
              present) echo "Name:      $4"; echo "MediaType: application/vnd.oci.image.index.v1+json"; exit 0 ;;
              absent)  echo "ERROR: $4: not found"; exit 1 ;;
              denied)  echo "ERROR: failed to authorize: denied: denied"; exit 1 ;;
              *)       echo "ERROR: dial tcp 140.82.112.33:443: connect: connection refused"; exit 1 ;;
            esac
            """;

    @TempDir
    Path tmp;

    @Test
    @DisplayName("the overwrite guard runs under bash -e (no shell: key, no defaults: block)")
    void stepRunsUnderBashE() throws IOException {
        List<String> lines = read(".github/workflows/release.yml");
        assertThat(lines).as("release.yml must not set defaults (e.g. defaults.run.shell)")
                .noneMatch(l -> l.strip().startsWith("defaults:"));
        int start = stepIndex(lines);
        int indent = indentOf(lines.get(start));
        for (int i = start + 1; i < lines.size(); i++) {
            String l = lines.get(i);
            if (!l.isBlank() && indentOf(l) <= indent) {
                break;
            }
            assertThat(l.strip()).as("the step sets no shell:, so it runs as bash -e {0}")
                    .doesNotStartWith("shell:");
        }
    }

    @Test
    @DisplayName("under bash -e, an image that is not published yet lets the release continue")
    void absentImageContinues() throws Exception {
        Result r = runStep("absent");
        assertThat(r.probed).as("the step probed the registry").isTrue();
        assertThat(r.exit).as("exit code; output was: %s", r.output).isZero();
        assertThat(r.output).contains(REF + " is not published yet.");
    }

    @Test
    @DisplayName("under bash -e, GHCR's 'denied' for a package that does not exist yet also continues")
    void deniedImageContinues() throws Exception {
        Result r = runStep("denied");
        assertThat(r.probed).as("the step probed the registry").isTrue();
        assertThat(r.exit).as("exit code; output was: %s", r.output).isZero();
        assertThat(r.output).contains(REF + " is not published yet.");
    }

    @Test
    @DisplayName("under bash -e, a published version is refused")
    void presentImageIsRefused() throws Exception {
        Result r = runStep("present");
        assertThat(r.probed).as("the step probed the registry").isTrue();
        assertThat(r.exit).as("exit code; output was: %s", r.output).isEqualTo(1);
        assertThat(r.output).contains("::error::" + REF + " already exists.");
    }

    @Test
    @DisplayName("under bash -e, any other probe failure fails closed with its reason")
    void otherErrorFailsClosed() throws Exception {
        Result r = runStep("other");
        assertThat(r.probed).as("the step probed the registry").isTrue();
        assertThat(r.exit).as("exit code; output was: %s", r.output).isEqualTo(1);
        assertThat(r.output)
                .contains("::error::could not tell whether " + REF + " exists (exit 1)")
                .contains("connection refused");
    }

    private record Result(int exit, String output, boolean probed) {
    }

    private Result runStep(String mode) throws Exception {
        Path script = tmp.resolve("step.sh");
        Files.writeString(script, runBlock(read(".github/workflows/release.yml")), StandardCharsets.UTF_8);
        Path bin = Files.createDirectories(tmp.resolve("bin"));
        Path docker = bin.resolve("docker");
        Files.writeString(docker, DOCKER_STUB, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(docker, PosixFilePermissions.fromString("rwxr-xr-x"));
        Path marker = tmp.resolve("probed-" + mode);

        // Exactly how Actions runs a step without shell: -> bash -e {0}
        ProcessBuilder pb = new ProcessBuilder("bash", "-e", script.toString())
                .directory(tmp.toFile())
                .redirectErrorStream(true);
        pb.environment().put("PATH", bin + ":" + System.getenv().getOrDefault("PATH", "/usr/bin:/bin"));
        pb.environment().put("STUB_MODE", mode);
        pb.environment().put("STUB_MARKER", marker.toString());
        pb.environment().put("REGISTRY", "ghcr.io");
        pb.environment().put("IMAGE_NAME", "hugmesh/hugmesh-admin-bff-api");
        pb.environment().put("VERSION", "0.0.1-beta.1");
        Process p = pb.start();
        p.getOutputStream().close();
        String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertThat(p.waitFor(30, TimeUnit.SECONDS)).as("the step finished").isTrue();
        return new Result(p.exitValue(), output, Files.exists(marker));
    }

    /** The step's {@code run: |} body, dedented, as Actions writes it to {0}. */
    private static String runBlock(List<String> lines) {
        int start = stepIndex(lines);
        int stepIndent = indentOf(lines.get(start));
        int run = -1;
        for (int i = start + 1; i < lines.size(); i++) {
            String l = lines.get(i);
            if (!l.isBlank() && indentOf(l) <= stepIndent) {
                break;
            }
            if (l.strip().equals("run: |")) {
                run = i;
                break;
            }
        }
        assertThat(run).as("the step has a 'run: |' block").isPositive();
        int runIndent = indentOf(lines.get(run));
        List<String> body = new ArrayList<>();
        for (int i = run + 1; i < lines.size(); i++) {
            String l = lines.get(i);
            if (!l.isBlank() && indentOf(l) <= runIndent) {
                break;
            }
            body.add(l);
        }
        int dedent = body.stream().filter(l -> !l.isBlank()).mapToInt(ReleaseOverwriteGuardExecutionTest::indentOf)
                .findFirst().orElseThrow(() -> new AssertionError("the run block is empty"));
        StringBuilder out = new StringBuilder();
        for (String l : body) {
            out.append(l.isBlank() ? "" : l.substring(dedent)).append('\n');
        }
        String script = out.toString();
        assertThat(script).as("the run block still probes the registry")
                .contains("docker buildx imagetools inspect");
        return script;
    }

    private static int stepIndex(List<String> lines) {
        int found = -1;
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).strip().equals(STEP)) {
                assertThat(found).as("exactly one step named '%s'", STEP.substring(8)).isEqualTo(-1);
                found = i;
            }
        }
        assertThat(found).as("release.yml has a step named '%s'", STEP.substring(8)).isNotNegative();
        return found;
    }

    private static int indentOf(String line) {
        return line.length() - line.stripLeading().length();
    }

    private static List<String> read(String relative) throws IOException {
        Path p = ROOT.resolve(relative);
        assertThat(p).as("%s must exist", relative).exists();
        return List.of(Files.readString(p, StandardCharsets.UTF_8).split("\n", -1));
    }
}
