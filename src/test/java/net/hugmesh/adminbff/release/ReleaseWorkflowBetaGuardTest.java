package net.hugmesh.adminbff.release;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the beta release scheme (2026-10-21) for this service's image.
 *
 * <ul>
 *   <li><b>Version.</b> The pom {@code <version>} is the image version and the git tag
 *       ({@code v<version>}). It must be {@code MAJOR.MINOR.PATCH-beta.N}: never a SNAPSHOT,
 *       never {@code +build} metadata (an OCI tag rejects {@code +}).</li>
 *   <li><b>Runner.</b> version and github-release use the one publish expression that
 *       picks {@code vars.RUNS_ON_PUBLISH} (the self-hosted runner) only for a non-PR run on
 *       main or a {@code v*} tag. A job with any other {@code runs-on} could send a run from
 *       any ref to the self-hosted runner. The signed image job (build-and-push) and
 *       notify-site run on literal hosted {@code ubuntu-latest} (see
 *       {@code ReleaseSignedImageGuardTest}): a published image is never built on the
 *       self-hosted runner.</li>
 *   <li><b>No pull request trigger.</b> The repositories go public; a pull request must never
 *       reach a workflow that can run on the self-hosted runner.</li>
 *   <li><b>Never {@code :latest}.</b> Every version today is a beta, and a beta never moves
 *       {@code latest}.</li>
 * </ul>
 *
 * <p>Reads the repository files directly (surefire runs with the project basedir as the
 * working directory). Whole-line comments are dropped first, so prose that explains why
 * something is absent cannot satisfy or defeat a check.
 */
class ReleaseWorkflowBetaGuardTest {

    private static final Path ROOT = Path.of("").toAbsolutePath();

    /** The scheme's runner line, verbatim. */
    static final String PUBLISH_RUNS_ON = "${{ fromJSON(github.event_name != 'pull_request'"
            + " && github.event_name != 'pull_request_target'"
            + " && (github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')"
            + " || startsWith(github.ref, 'refs/tags/studio-v'))"
            + " && vars.RUNS_ON_PUBLISH || '\"ubuntu-latest\"') }}";

    private static final Pattern BETA_VERSION = Pattern.compile("^\\d+\\.\\d+\\.\\d+-beta\\.[1-9]\\d*$");

    @Test
    @DisplayName("pom <version> is a beta coordinate (MAJOR.MINOR.PATCH-beta.N), never a SNAPSHOT")
    void pomVersionIsBeta() throws Exception {
        String version = projectVersion();
        assertThat(version).as("pom.xml <project><version>").matches(BETA_VERSION);
    }

    @Test
    @DisplayName("release.yml: version and github-release run on the publish expression, the signed jobs on hosted ubuntu-latest")
    void everyJobUsesThePublishRunnerExpression() throws IOException {
        String yaml = code(read(".github/workflows/release.yml"));
        List<String> runsOn = new ArrayList<>();
        List<String> names = new ArrayList<>();
        int jobs = 0;
        boolean inJobs = false;
        for (String line : yaml.split("\n")) {
            if (line.equals("jobs:")) {
                inJobs = true;
                continue;
            }
            if (inJobs && Pattern.matches("^  [A-Za-z0-9_-]+:\\s*$", line)) {
                jobs++;
                names.add(line.strip().replace(":", ""));
            }
            String t = line.strip();
            if (t.startsWith("runs-on:")) {
                runsOn.add(t.substring("runs-on:".length()).strip());
            }
        }
        assertThat(jobs).as("number of jobs").isGreaterThan(0);
        assertThat(runsOn).as("one runs-on per job").hasSize(jobs);
        assertThat(names).as("jobs in order")
                .containsExactly("version", "build-and-push", "github-release", "notify-site");
        assertThat(runsOn).as("runs-on per job, in job order")
                .containsExactly(PUBLISH_RUNS_ON, "ubuntu-latest", PUBLISH_RUNS_ON, "ubuntu-latest");
        assertThat(yaml.replace("vars.RUNS_ON_PUBLISH", ""))
                .as("the PR-era RUNS_ON variable is never read")
                .doesNotContain("RUNS_ON");
    }

    @Test
    @DisplayName("release.yml has no pull_request / pull_request_target trigger")
    void noPullRequestTrigger() throws IOException {
        String yaml = code(read(".github/workflows/release.yml")).replace(PUBLISH_RUNS_ON, "");
        assertThat(yaml).as("pull_request anywhere outside the runner expression").doesNotContain("pull_request");
        assertThat(yaml).as("publishes on main, v* tags and dispatch")
                .contains("branches: [main]")
                .contains("tags: ['v*']")
                .contains("workflow_dispatch");
    }

    @Test
    @DisplayName("release.yml guards the tag against the pom, never pushes :latest, releases a beta as prerelease")
    void versionGuardAndTags() throws IOException {
        String yaml = code(read(".github/workflows/release.yml"));
        assertThat(yaml)
                .as("a v* tag must equal v<pom version>")
                .contains("\"${GITHUB_REF_NAME#v}\" != \"${version}\"")
                .as("SNAPSHOT is refused")
                .contains("*-SNAPSHOT)")
                .as("an existing :<version> is never overwritten")
                .contains("docker buildx imagetools inspect")
                .as("a beta release is a prerelease and never latest")
                .contains("--prerelease --latest=false");
        assertThat(yaml).as("no :latest image tag and no release marked latest")
                .doesNotContainPattern(":latest\\b|value=latest|latest=(true|auto)|--latest(?!=false)|make_latest:\\s*true");
        assertThat(yaml).as("the preflight still precedes the image build")
                .contains("Preflight, cross-repo package read");
        assertThat(yaml.indexOf("Preflight, cross-repo package read"))
                .isLessThan(yaml.indexOf("docker/build-push-action"));
    }

    private static String projectVersion() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Document doc = f.newDocumentBuilder().parse(ROOT.resolve("pom.xml").toFile());
        NodeList children = doc.getDocumentElement().getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n instanceof Element e && e.getTagName().equals("version")) {
                return e.getTextContent().strip();
            }
        }
        throw new AssertionError("pom.xml has no <project><version>");
    }

    private static String read(String relative) throws IOException {
        Path p = ROOT.resolve(relative);
        assertThat(p).as("%s must exist", relative).exists();
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    /** Drops whole-line comments so prose cannot satisfy or defeat a check. */
    private static String code(String text) {
        StringBuilder out = new StringBuilder();
        for (String line : text.split("\n", -1)) {
            if (!line.stripLeading().startsWith("#")) {
                out.append(line).append('\n');
            }
        }
        return out.toString();
    }
}
