package net.hugmesh.adminbff;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * STRUCTURAL guard: no {@code revokeSubject(...)} call in {@code src/main} may pass a numeric
 * literal as its TTL.
 *
 * <p>Every one of the five call sites used to pass {@code 3_600L}, each with a comment calling it
 * "the custody JWT lifetime (~1 h)". The seeded Casdoor apps issue 168 h tokens, so the literal
 * was wrong at every cut-off site and nothing tied it to the number it claimed to mirror. The
 * TTL now comes from configuration ({@link SubjectRevocationTtl}) or a named constant whose
 * javadoc says why it is short. A new call site that types a literal again fails here.
 *
 * <p>Documented limit: this reads source text. It sees the third argument of each call as
 * written, so a literal hidden behind a local variable is invisible to it; the controller and
 * sync tests pin the VALUES that reach the client.
 */
class RevokeSubjectTtlSourceGuardTest {

    private static final Path MAIN = Path.of("src/main/java");
    private static final Pattern NUMERIC_LITERAL = Pattern.compile("[0-9][0-9_]*[lL]?");

    @Test
    void noRevokeSubjectCallPassesALiteralTtl() throws IOException {
        assertThat(MAIN).as("run from the module root").isDirectory();
        List<String> offenders = new ArrayList<>();
        int calls = 0;
        try (Stream<Path> files = Files.walk(MAIN)) {
            for (Path f : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String src = Files.readString(f, StandardCharsets.UTF_8);
                int at = 0;
                while ((at = src.indexOf(".revokeSubject(", at)) >= 0) {
                    int open = at + ".revokeSubject".length();
                    List<String> args = topLevelArgs(src, open);
                    calls++;
                    if (args.size() == 3 && NUMERIC_LITERAL.matcher(args.get(2).strip()).matches()) {
                        offenders.add(MAIN.relativize(f) + ": revokeSubject(" + String.join(",", args) + ")");
                    }
                    at = open;
                }
            }
        }
        // Anti-vacuity: the scan must actually see the call sites (account-disable, role
        // grant/revoke, desktop-sudo grant/revoke, suspension enforcement).
        assertThat(calls).as("revokeSubject call sites found under src/main/java").isGreaterThanOrEqualTo(6);
        assertThat(offenders)
                .as("revokeSubject TTL must come from SubjectRevocationTtl config or a named constant, "
                        + "never a literal: a 1 h literal let a 168 h Casdoor token outlive its revocation")
                .isEmpty();
    }

    /** Split the argument list starting at {@code src.charAt(open) == '('} on top-level commas. */
    private static List<String> topLevelArgs(String src, int open) {
        List<String> args = new ArrayList<>();
        int depth = 0;
        StringBuilder cur = new StringBuilder();
        for (int i = open; i < src.length(); i++) {
            char c = src.charAt(i);
            if (c == '(') {
                if (depth++ == 0) continue;
            } else if (c == ')') {
                if (--depth == 0) {
                    args.add(cur.toString());
                    return args;
                }
            } else if (c == ',' && depth == 1) {
                args.add(cur.toString());
                cur.setLength(0);
                continue;
            }
            cur.append(c);
        }
        return args;
    }
}
