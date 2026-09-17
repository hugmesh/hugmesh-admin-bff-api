package net.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * THE CROSS-REPO DRIFT PIN (issue #55; operator decision 37, hugmesh-generator#347).
 *
 * <p>{@code src/main/resources/schema/app-profile.schema.json} is a BYTE-IDENTICAL copy of
 * {@code schemas/app-profile.schema.json} in hugmesh-superadmin-service-catalog-ui, and
 * {@link AppProfileService} validates every app-profile save against it. The copy only buys
 * anything while it is actually identical: the moment either side is edited alone, the console
 * and the server refuse different bodies — the operator is told a template is fine and the save
 * 400s, or a template the console refused is accepted through the API and later rejected in the
 * editor.
 *
 * <p>So BOTH copies are pinned to the SAME sha256 literal:
 * <ul>
 *   <li>here — this test;</li>
 *   <li>there — {@code scripts/assert-schema-pin.mjs}, which runs first inside {@code npm test}.</li>
 * </ul>
 * Editing the schema turns BOTH suites red until both copies and both pins move in one change.
 * That is the point. The pin is not here to bless the current bytes; it is here to make a
 * one-sided edit impossible to land quietly.
 *
 * <p>This deliberately hashes the RESOURCE BYTES, not a re-serialisation of the parsed tree: two
 * files that parse to the same tree are not the same file, and "byte-identical" is the property
 * the contract names.
 */
class AppProfileSchemaMirrorTest {

    /**
     * sha256 of {@code schemas/app-profile.schema.json} on
     * hugmesh-superadmin-service-catalog-ui {@code main} @{@code 29a2073} (PR #13, merged
     * 2026-09-16) — the version operator decision 37 ratified.
     */
    static final String PINNED_SHA256 =
            "12c581265335a2f91808841c66db546bbd222375392e0d8c23270d82619e8969";

    /** Where the other copy lives, named in the failure so the fix is obvious. */
    private static final String MIRROR =
            "hugmesh-superadmin-service-catalog-ui schemas/app-profile.schema.json";

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
                          4. run both suites.""",
                        AppProfileSchema.RESOURCE, PINNED_SHA256, actual, MIRROR,
                        AppProfileSchema.RESOURCE, actual)
                .isEqualTo(PINNED_SHA256);
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
