package net.hugmesh.adminbff;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Repo-wide guard against HTTP-status assertions that compare {@link HttpStatus} ENUM IDENTITY
 * instead of the numeric status code.
 *
 * <p>Why this exists: {@code HttpStatus} is an enum in which several HTTP codes have TWO
 * constants — an RFC-9110 name and a legacy alias (422 is both {@code UNPROCESSABLE_CONTENT}
 * and {@code UNPROCESSABLE_ENTITY}; 413 is both {@code CONTENT_TOO_LARGE} and
 * {@code PAYLOAD_TOO_LARGE}). Those constants are NOT {@code equals()} to one another, even
 * though {@code value()} is identical. Anything that reconstructs a status from the wire goes
 * through {@code HttpStatusCode.valueOf(int)}, which always yields the CANONICAL constant. So
 * {@code expectStatus().isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY)} fails against a real 422
 * response with the useless diagnostic
 * {@code expected:<422 UNPROCESSABLE_ENTITY> but was:<422 UNPROCESSABLE_CONTENT>} — a Spring
 * Framework rename, not a behaviour change. That is exactly how this repo acquired 8 red tests
 * on the Boot 4.0.7 / Framework 7.0.8 baseline.
 *
 * <p>The alias set below is DERIVED from the {@code HttpStatus} enum on the build classpath, not
 * hand-listed, so a future Spring rename is caught the same way.
 */
class HttpStatusAssertionStyleTest {

    private static final Path MAIN = Path.of("src", "main", "java");
    private static final Path TEST = Path.of("src", "test", "java");

    /** This file necessarily talks about the very patterns it bans. */
    private static final String SELF = "HttpStatusAssertionStyleTest.java";

    /** {@code isEqualTo(HttpStatus.X)} / {@code assertEquals(HttpStatus.X, ...)} and friends. */
    private static final Pattern ENUM_IDENTITY_ASSERTION = Pattern.compile(
            "(?:isEqualTo|isNotEqualTo|isSameAs)\\(\\s*(?:org\\.springframework\\.http\\.)?"
                    + "HttpStatus\\.[A-Z_0-9]+\\s*\\)"
                    + "|assertEquals\\(\\s*(?:org\\.springframework\\.http\\.)?HttpStatus\\.[A-Z_0-9]+");

    @Test
    void noAssertionComparesHttpStatusEnumIdentity() {
        List<String> offenders = scan(TEST, ENUM_IDENTITY_ASSERTION);
        assertThat(offenders)
                .as("assert the numeric status code (e.g. .isEqualTo(422), or "
                        + "assertThat(x.getStatusCode().value()).isEqualTo(422)) — comparing HttpStatus "
                        + "enum identity breaks on a Spring constant rename even though the wire "
                        + "behaviour is unchanged")
                .isEmpty();
    }

    @Test
    void noSourceReferencesADeprecatedHttpStatusAlias() {
        Set<String> aliases = nonCanonicalAliases();
        assertThat(aliases)
                .as("sanity: the Spring baseline is expected to carry at least one aliased status")
                .isNotEmpty();

        Pattern aliasUse = Pattern.compile("HttpStatus\\.(?:" + String.join("|", aliases) + ")\\b");
        List<String> offenders = new ArrayList<>();
        offenders.addAll(scan(MAIN, aliasUse));
        offenders.addAll(scan(TEST, aliasUse));
        assertThat(offenders)
                .as("use the canonical constant for the code (aliases resolved from the enum: %s) — "
                        + "HttpStatusCode.valueOf(int) never returns the alias, so anything compared "
                        + "against a round-tripped status will not match it", aliases)
                .isEmpty();
    }

    /**
     * Pins the mechanism the two guards above defend against, so the reason survives even if the
     * offending call sites are all gone: aliased constants share a code but are not equal.
     */
    @Test
    void aliasedConstantsShareACodeButAreNotEqual() {
        Map<Integer, List<HttpStatus>> byCode = new LinkedHashMap<>();
        for (HttpStatus s : HttpStatus.values()) {
            byCode.computeIfAbsent(s.value(), k -> new ArrayList<>()).add(s);
        }
        List<List<HttpStatus>> aliased = byCode.values().stream().filter(g -> g.size() > 1).toList();
        assertThat(aliased).as("Spring baseline is expected to carry aliased status constants").isNotEmpty();

        for (List<HttpStatus> group : aliased) {
            HttpStatus canonical = (HttpStatus) HttpStatusCode.valueOf(group.get(0).value());
            for (HttpStatus alias : group) {
                assertThat(alias.value())
                        .as("%s and %s are the same HTTP code", alias.name(), canonical.name())
                        .isEqualTo(canonical.value());
                if (alias != canonical) {
                    assertThat(alias)
                            .as("%s is NOT equal to %s despite both being %d — this is the trap",
                                    alias.name(), canonical.name(), alias.value())
                            .isNotEqualTo(canonical);
                }
            }
        }
    }

    /** Constants that share their code with the one {@code HttpStatusCode.valueOf(int)} returns. */
    private static Set<String> nonCanonicalAliases() {
        Set<String> aliases = new TreeSet<>();
        for (HttpStatus s : HttpStatus.values()) {
            if (HttpStatusCode.valueOf(s.value()) != s) {
                aliases.add(s.name());
            }
        }
        return aliases;
    }

    private static List<String> scan(Path root, Pattern forbidden) {
        assertThat(Files.isDirectory(root)).as("source root %s must exist", root).isTrue();
        List<String> hits = new ArrayList<>();
        int scanned = 0;
        try (Stream<Path> files = Files.walk(root)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                if (file.getFileName().toString().equals(SELF)) {
                    continue;
                }
                scanned++;
                String[] lines;
                try {
                    lines = Files.readString(file).split("\n", -1);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
                for (int i = 0; i < lines.length; i++) {
                    Matcher m = forbidden.matcher(lines[i]);
                    if (m.find()) {
                        hits.add(root.relativize(file) + ":" + (i + 1) + "  " + lines[i].strip());
                    }
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        // A scanner that silently walked nothing would pass vacuously.
        assertThat(scanned).as("expected to scan real sources under %s", root).isGreaterThan(50);
        return hits;
    }
}
