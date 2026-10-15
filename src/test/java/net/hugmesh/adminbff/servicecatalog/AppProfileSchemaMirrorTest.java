package net.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * THE CROSS-REPO DRIFT GUARD (issue #55; operator decision 37, hugmesh-generator#347).
 *
 * <p>{@code src/main/resources/schema/app-profile.schema.json} is a BYTE-IDENTICAL copy of
 * {@code schemas/app-profile.schema.json} in hugmesh-superadmin-service-catalog-ui, and
 * {@link AppProfileService} validates every app-profile save against it. The copy only buys
 * anything while it is actually identical: the moment either side is edited alone, the console
 * and the server refuse different bodies — the operator is told a template is fine and the save
 * 400s, or a template the console refused is accepted through the API and later rejected in the
 * editor.
 *
 * <h2>Two checks, and they catch different things</h2>
 *
 * <p><b>1. The local pin</b> ({@link #theCommittedSchemaCopyIsByteIdenticalToTheConsoleCopy}).
 * {@link #PINNED_SHA256} is compared against OUR OWN resource bytes. It makes editing the schema
 * a deliberate act — you cannot change it without also moving a literal — but on its own it
 * proves NOTHING about the console repo. Moving the schema and the literal together in ONE repo
 * satisfies the local pin in that repo completely.
 *
 * <p>That was the entire hole in the first version of this guard, and it was not theoretical: a
 * reviewer widened {@code certs.ttl} {@code maxLength} 32 -> 64 in the console copy, moved only
 * the console's {@code PINNED}, and got BOTH suites green with the two files diverged
 * ({@code cmp} -> {@code differ: char 4898, line 63}) — while the console's pin script printed
 * "mirrored byte-for-byte by hugmesh-admin-bff-api ...", a sentence it had never checked.
 *
 * <p><b>2. The mirror check</b> ({@link #theConsoleCopyIsByteForByteIdenticalToThisOne}). When
 * the console checkout is reachable, the two FILES are compared byte for byte. This is the check
 * that enforces the contract, and the only one that can see a one-sided edit.
 *
 * <h2>Why the skip is safe here and nowhere else</h2>
 *
 * <p>The mirror check SKIPS when the console checkout is absent, because a downstream build of
 * this service alone cannot be expected to have it. A skip that nobody notices is how
 * {@code ImageCatalogDriftTest} sat dark in CI for months — green locally, checking nothing in
 * the pipeline. So CI does not rely on the default: {@code .gitlab-ci.yml} clones the console,
 * asserts the schema file by name, and passes
 * {@code -Dappprofile.schema.mirror.required=true}, which turns the skip into a FAILURE. Locally
 * the sibling checkout satisfies it with no flags.
 *
 * <p>The pin deliberately hashes the RESOURCE BYTES, not a re-serialisation of the parsed tree:
 * two files that parse to the same tree are not the same file, and "byte-identical" is the
 * property the contract names.
 */
class AppProfileSchemaMirrorTest {

    /**
     * sha256 of {@code schemas/app-profile.schema.json} on
     * hugmesh-superadmin-service-catalog-ui {@code main} @{@code 29a2073} (PR #13, merged
     * 2026-09-16) — the version operator decision 37 ratified. The trailing marker is
     * load-bearing: it is how a human grepping either repo finds both literals in one search.
     * The console's is {@code PINNED} in {@code scripts/assert-schema-pin.mjs}.
     */
    static final String PINNED_SHA256 =
            "12c581265335a2f91808841c66db546bbd222375392e0d8c23270d82619e8969"; // HUGMESH-SCHEMA-PIN

    /** Where the other copy lives, named in the failure so the fix is obvious. */
    private static final String MIRROR =
            "hugmesh-superadmin-service-catalog-ui schemas/app-profile.schema.json";

    /** The console's schema DIRECTORY; the pom defaults it to a sibling checkout. */
    private static final String CONSOLE_DIR_PROPERTY = "appprofile.schema.console.dir";

    /** Set by CI so an absent console checkout FAILS instead of skipping. */
    private static final String REQUIRED_PROPERTY = "appprofile.schema.mirror.required";

    private static Path consoleCopy() {
        String dir = System.getProperty(CONSOLE_DIR_PROPERTY, "");
        return dir.isBlank() ? null : Path.of(dir).resolve("app-profile.schema.json");
    }

    @Test
    void theCommittedSchemaCopyIsByteIdenticalToTheConsoleCopy() throws NoSuchAlgorithmException {
        byte[] bytes = AppProfileSchema.resourceBytes();
        String actual = hex(MessageDigest.getInstance("SHA-256").digest(bytes));

        assertThat(actual)
                .withFailMessage("""
                        %s has changed.
                          expected sha256 %s
                          actual   sha256 %s

                        This file is a BYTE-IDENTICAL mirror of %s, and this service validates every
                        app-profile save against it. A one-sided edit makes the console and the server
                        refuse different bodies.

                        To change the schema on purpose, in ONE change:
                          1. edit the console copy;
                          2. copy it byte-identically over %s here;
                          3. update PINNED_SHA256 here AND PINNED in scripts/assert-schema-pin.mjs there
                             to %s;
                          4. run both suites, with both checkouts present so the mirror check runs.""",
                        AppProfileSchema.RESOURCE, PINNED_SHA256, actual, MIRROR,
                        AppProfileSchema.RESOURCE, actual)
                .isEqualTo(PINNED_SHA256);
    }

    /**
     * THE CHECK THAT ACTUALLY ENFORCES THE CONTRACT: read the console's file and compare bytes.
     *
     * <p>A local sha256 literal cannot do this. Two literals that happen to be spelled the same
     * are still two independent assertions about two independent files, and moving one of them
     * is a one-line change that no test in either repo objects to. Only reading the other file
     * can tell you the copies are the same.
     */
    @Test
    void theConsoleCopyIsByteForByteIdenticalToThisOne() throws IOException {
        Path console = consoleCopy();
        boolean required = Boolean.getBoolean(REQUIRED_PROPERTY);
        boolean present = console != null && Files.isRegularFile(console);

        if (required && !present) {
            throw new AssertionError("""
                    -D%s=true is set (CI), so the console checkout MUST be present, and it is not:
                      looked for: %s
                      -D%s=%s

                    CI clones hugmesh-superadmin-service-catalog-ui for exactly this check. A missing
                    checkout means that clone failed. Fix the clone - do NOT drop the flag, or this
                    guard goes back to being green while checking nothing."""
                    .formatted(REQUIRED_PROPERTY, console, CONSOLE_DIR_PROPERTY,
                            System.getProperty(CONSOLE_DIR_PROPERTY, "<unset>")));
        }

        assumeTrue(present,
                "console checkout not present (" + console + ") - the byte-identity of the two copies "
                        + "is UNVERIFIED on this run; the local sha256 pin cannot see a one-sided edit. "
                        + "CI sets -" + REQUIRED_PROPERTY + "=true so this never skips there.");

        byte[] mine = AppProfileSchema.resourceBytes();
        byte[] theirs = Files.readAllBytes(console);

        if (!Arrays.equals(mine, theirs)) {
            int at = 0;
            int max = Math.min(mine.length, theirs.length);
            while (at < max && mine[at] == theirs[at]) {
                at++;
            }
            long line = new String(mine, 0, at, java.nio.charset.StandardCharsets.UTF_8)
                    .chars().filter(c -> c == '\n').count() + 1;
            throw new AssertionError("""
                    THE TWO SCHEMA COPIES HAVE DRIFTED.
                      here  %s            (%d bytes)
                      there %s  (%d bytes)
                      first difference at byte %d (line %d)

                    The console and this service are now validating app-profile JSON against DIFFERENT
                    schemas: one of them accepts a body the other refuses. This is the exact failure the
                    byte-identical copy exists to prevent, and the sha256 LITERAL cannot see it - which
                    is why this test reads the other repo instead of trusting a matching literal.

                    Fix it in ONE change: make the two files identical, then set PINNED_SHA256 here and
                    PINNED in scripts/assert-schema-pin.mjs there to the same hash, and run both suites."""
                    .formatted(AppProfileSchema.RESOURCE, mine.length, console, theirs.length, at, line));
        }
    }

    @Test
    void theCopyIsReadableAsJsonAndIsTheSchemaTheValidatorUses() {
        assertThat(AppProfileSchema.schema().path("$id").asText()).isEqualTo("urn:hugmesh:schema:app-profile");
        assertThat(AppProfileSchema.schema().path("$schema").asText())
                .isEqualTo("https://json-schema.org/draft/2020-12/schema");
    }

    private static String hex(byte[] digest) {
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
