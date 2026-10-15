package net.hugmesh.adminbff.workload;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The generator-curated allowlists + gate semantics (fail-closed). */
class WorkloadConsolePropertiesTest {

    /**
     * A COPY of the value hugmesh-generator emits for {@code WORKLOAD_CONSOLE_EXEC_READONLY}
     * ({@code specs/cluster/manifests/admin-bff-api/workload-console-patch.yaml} at generator
     * commit 2be93a0). It is a fixture, not a live read: a later change on the generator side
     * does NOT turn this test red (the generator's own tests/workload-console suite guards the
     * value). What it pins is that the SHAPE the generator uses — bare names (any arguments)
     * mixed with space-joined pinned argvs (exact), one comma-delimited env string — binds
     * and matches the way
     * {@link WorkloadConsoleProperties#execReadOnlyAllowed} documents.
     */
    private static final String GENERATOR_SHIPPED_EXEC_READONLY =
            "ls,df -h,free,uptime,id,uname,stat -t,ps -e,date -u";

    private static WorkloadConsoleProperties withExec(String... entries) {
        WorkloadConsoleProperties p = new WorkloadConsoleProperties();
        p.setExecReadOnlyCommands(Arrays.asList(entries));
        return p;
    }

    /** Bind {@code app.workload-console.exec-read-only-commands} from ONE string, exactly as
     *  the env var reaches Spring (the application.yml placeholder is a plain string). */
    private static WorkloadConsoleProperties bindExec(String raw) {
        Binder binder = new Binder(new MapConfigurationPropertySource(
                Map.of("app.workload-console.exec-read-only-commands", raw)));
        return binder.bind("app.workload-console", WorkloadConsoleProperties.class)
                .orElseGet(WorkloadConsoleProperties::new);
    }

    @Test
    void defaults_areDark_andFailClosed() {
        WorkloadConsoleProperties p = new WorkloadConsoleProperties();
        assertThat(p.isEnabled()).isFalse();
        // empty allowlist rejects every namespace (fail-closed)
        assertThat(p.namespaceAllowed("hugmesh-app")).isFalse();
        assertThat(p.namespaceAllowed(null)).isFalse();
        assertThat(p.portForwardAllowed("ns", "wl", 8080)).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("ls"))).isFalse();
    }

    @Test
    void namespaceAllowlist_membership() {
        WorkloadConsoleProperties p = new WorkloadConsoleProperties();
        p.setNamespaceAllowlist(List.of("hugmesh-app", "hugmesh-forum"));
        assertThat(p.namespaceAllowed("hugmesh-app")).isTrue();
        assertThat(p.namespaceAllowed("hugmesh-pki")).isFalse(); // infra tier excluded
    }

    @Test
    void portForwardAllowlist_exactTripleMatch() {
        WorkloadConsoleProperties p = new WorkloadConsoleProperties();
        var t = new WorkloadConsoleProperties.PortForwardTarget();
        t.setNamespace("hugmesh-app");
        t.setWorkload("web");
        t.setPort(8080);
        p.setPortForwardAllowlist(List.of(t));
        assertThat(p.portForwardAllowed("hugmesh-app", "web", 8080)).isTrue();
        assertThat(p.portForwardAllowed("hugmesh-app", "web", 5432)).isFalse(); // wrong port
        assertThat(p.portForwardAllowed("hugmesh-pki", "web", 8080)).isFalse();
    }

    // ── read-only exec: BARE NAME = head + any args; PINNED ARGV = exact whole argv ─────

    /** The generator's PINNED forms are reachable. Under the old first-token matcher every
     *  one of these was refused — no head token equals a string containing a space. */
    @Test
    void execReadOnly_exactMultiWordEntry_isAllowed() {
        WorkloadConsoleProperties p = withExec("ps -e", "date -u", "df -h", "stat -t");
        assertThat(p.execReadOnlyAllowed(List.of("ps", "-e"))).isTrue();
        assertThat(p.execReadOnlyAllowed(List.of("date", "-u"))).isTrue();
        assertThat(p.execReadOnlyAllowed(List.of("df", "-h"))).isTrue();
        assertThat(p.execReadOnlyAllowed(List.of("stat", "-t"))).isTrue();
        // and a bare entry still matches its own one-token argv
        assertThat(withExec("ls").execReadOnlyAllowed(List.of("ls"))).isTrue();
    }

    /** No prefix match on a PINNED argv: a pinned argv followed by ANYTHING is a different
     *  argv. These are the exact escapes the generator pinned against (ps eww = every
     *  environment, date -f FILE = FILE's lines echoed back, df --output/--sync). */
    @Test
    void execReadOnly_extraArgsOnPinnedEntry_areRejected() {
        WorkloadConsoleProperties p = withExec("ls", "ps -e", "date -u", "df -h");
        assertThat(p.execReadOnlyAllowed(List.of("ps", "-e", "eww"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("ps", "-e", "e"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of(
                "date", "-u", "-f", "/var/run/secrets/workload-console-read/token"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("df", "-h", "--sync"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("df", "-h", "/var/run/secrets"))).isFalse();
        // a trailing empty-string argument is still an extra argument
        assertThat(p.execReadOnlyAllowed(List.of("ps", "-e", ""))).isFalse();
    }

    /** A BARE NAME keeps licensing its command with ARBITRARY arguments — the generator's
     *  "argument-safe" form, audited under arbitrary argv before a name ships bare. The
     *  arguments go to the command as argv elements, never through a shell, so shell-looking
     *  arguments are just file names; the HEAD itself must still equal the entry exactly. */
    @Test
    void execReadOnly_bareName_licensesArbitraryArguments_butOnlyItsExactHead() {
        WorkloadConsoleProperties p = withExec("ls", "uname", "ps -e");
        assertThat(p.execReadOnlyAllowed(List.of("ls"))).isTrue();
        assertThat(p.execReadOnlyAllowed(List.of("ls", "-la"))).isTrue();
        assertThat(p.execReadOnlyAllowed(List.of("ls", "-la", "/"))).isTrue();
        assertThat(p.execReadOnlyAllowed(List.of("uname", "-a"))).isTrue();
        assertThat(p.execReadOnlyAllowed(List.of("ls", "`env`"))).isTrue();
        // the head is matched char-for-char: no path resolution, case folding, trimming or
        // splitting of a head token that smuggles a second command
        assertThat(p.execReadOnlyAllowed(List.of("/bin/ls", "-la"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("LS"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of(" ls"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("ls;env"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("ls -la"))).isFalse();
        assertThat(p.execReadOnlyAllowed(Arrays.asList((String) null, "-la"))).isFalse();
        // a one-token entry is a bare name; a multi-token entry never becomes one by its head
        assertThat(p.execReadOnlyAllowed(List.of("ps", "eww"))).isFalse();
    }

    /** No head match: the first token of a pinned entry is not itself an entry, so neither
     *  the bare command nor the command with some OTHER flag is licensed. */
    @Test
    void execReadOnly_headOnlyOfMultiWordEntry_isRejected() {
        WorkloadConsoleProperties p = withExec("ps -e", "date -u", "stat -t");
        assertThat(p.execReadOnlyAllowed(List.of("ps"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("date"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("ps", "eww"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("stat", "-f", "/"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("stat", "--file-system", "/"))).isFalse();
        // nor the tail, nor the right tokens in the wrong order
        assertThat(p.execReadOnlyAllowed(List.of("-e"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("-e", "ps"))).isFalse();
    }

    /** No shell parsing and no normalisation: every one of these differs from an allowlisted
     *  argv in at least one token, char-for-char, so every one is refused. */
    @Test
    void execReadOnly_injectionishTokens_areRejected() {
        WorkloadConsoleProperties p = withExec("ls", "ps -e", "date -u");
        List<List<String>> refused = List.of(
                List.of("ps -e"),                          // ONE token; old matcher let it in
                List.of("ps", "-e;env"),
                List.of("ps", "-e", ";", "env"),
                List.of("ps", "-e", "&&", "env"),
                List.of("ps", "-e", "|", "cat", "/etc/shadow"),
                List.of("ps", "-e", "`env`"),
                List.of("date", "-u", "$(env)"),
                List.of("ls;env"),
                List.of("sh", "-c", "ps -e"),
                List.of("/bin/ps", "-e"),                  // no path resolution
                List.of("./ls"),
                List.of("PS", "-E"),                       // case-sensitive
                List.of(" ps", "-e"),                      // no trimming of request tokens
                List.of("ps", "-e "),
                List.of("ps", "-e\n"),
                List.of("ps\t-e"),
                List.of("ps", "", "-e"),
                List.of("", "ps", "-e"),
                List.of(""));
        for (List<String> argv : refused) {
            assertThat(p.execReadOnlyAllowed(argv)).as("argv %s", argv).isFalse();
        }
        // a null token (a JSON null inside the request array) is refused, not an NPE
        assertThat(p.execReadOnlyAllowed(Arrays.asList("ps", null))).isFalse();
        assertThat(p.execReadOnlyAllowed(Arrays.asList((String) null))).isFalse();
        assertThat(p.execReadOnlyAllowed(null)).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of())).isFalse();
        // the allowlisted argvs themselves still pass (the refusals above are not vacuous)
        assertThat(p.execReadOnlyAllowed(List.of("ps", "-e"))).isTrue();
        assertThat(p.execReadOnlyAllowed(List.of("ls"))).isTrue();
    }

    /** A malformed entry licenses NOTHING — including the odd argv a lenient split would have
     *  turned it into — while well-formed neighbours keep working. */
    @Test
    void execReadOnly_malformedEntries_licenseNothing() {
        WorkloadConsoleProperties p = withExec(
                "ps  -e", " date -u", "df -h ", "stat\t-t", "uname -a", "", null, "ls");
        assertThat(p.execReadOnlyAllowed(List.of("ps", "-e"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("ps", "", "-e"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("date", "-u"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("", "date", "-u"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("df", "-h"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("df", "-h", ""))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("stat\t-t"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("uname -a"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of(""))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of("ls"))).isTrue();

        assertThat(WorkloadConsoleProperties.entryArgv("ps -e")).containsExactly("ps", "-e");
        assertThat(WorkloadConsoleProperties.entryArgv("ps  -e")).isNull();
        assertThat(WorkloadConsoleProperties.entryArgv("")).isNull();
        assertThat(WorkloadConsoleProperties.entryArgv(null)).isNull();
    }

    /** End to end through Spring's binder: the generator's one comma-delimited env string
     *  arrives as whole entries ({@code "df -h"}, not {@code "df"} + {@code "-h"}), blanks
     *  around commas are trimmed by the binder (the javadoc of entryArgv relies on that), the
     *  five bare names take arguments, and the four pinned forms license exactly themselves. */
    @Test
    void execReadOnly_generatorShippedValue_bindsAndMatchesWholeArgv() {
        WorkloadConsoleProperties p = bindExec(GENERATOR_SHIPPED_EXEC_READONLY);
        assertThat(p.getExecReadOnlyCommands()).containsExactly(
                "ls", "df -h", "free", "uptime", "id", "uname", "stat -t", "ps -e", "date -u");

        for (List<String> argv : List.of(
                List.of("ls"), List.of("df", "-h"), List.of("free"), List.of("uptime"),
                List.of("id"), List.of("uname"), List.of("stat", "-t"), List.of("ps", "-e"),
                List.of("date", "-u"),
                // bare names with arguments (the generator audited them under arbitrary argv)
                List.of("ls", "-la", "/"), List.of("uname", "-a"), List.of("free", "-h"),
                List.of("id", "-u"), List.of("uptime", "-p"))) {
            assertThat(p.execReadOnlyAllowed(argv)).as("argv %s", argv).isTrue();
        }
        for (List<String> argv : List.of(
                List.of("ps"), List.of("ps", "eww"), List.of("date", "-f", "/etc/hostname"),
                List.of("df"), List.of("df", "--output=source,target",
                        "/var/run/secrets/workload-console-read/token"),
                List.of("stat", "-f", "/"), List.of("stat", "--file-system", "/"),
                List.of("stat", "-t", "/etc/hostname"), List.of("df", "-h", "/"))) {
            assertThat(p.execReadOnlyAllowed(argv)).as("argv %s", argv).isFalse();
        }

        // blanks around the commas: trimmed by the binder, so the entries still match
        WorkloadConsoleProperties spaced = bindExec(" ls , ps -e ");
        assertThat(spaced.getExecReadOnlyCommands()).containsExactly("ls", "ps -e");
        assertThat(spaced.execReadOnlyAllowed(List.of("ps", "-e"))).isTrue();
    }

    /** The shipped application.yml default is {@code ${WORKLOAD_CONSOLE_EXEC_READONLY:}} —
     *  an empty string. Whatever the binder turns that into, nothing is exec-able. */
    @Test
    void execReadOnly_emptyBoundValue_refusesEverything() {
        WorkloadConsoleProperties p = bindExec("");
        assertThat(p.execReadOnlyAllowed(List.of("ls"))).isFalse();
        assertThat(p.execReadOnlyAllowed(List.of(""))).isFalse();
    }
}
