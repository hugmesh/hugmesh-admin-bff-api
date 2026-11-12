package net.hugmesh.adminbff.imagegen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The generator platform set, read from the VENDORED worklist.v1 schema
 * ({@value #SCHEMA_RESOURCE}, a byte-for-byte copy of the generator's
 * {@code docs/schemas/worklist.v1.schema.json}; {@code WorklistSchemaDriftTest} asserts it has not
 * drifted). It replaces the hand-written {@code x86|rpi5|...} alternations that
 * {@link WorklistEnvelopeValidator} and {@link net.hugmesh.adminbff.web.dto.BatchImageSpec} used
 * to carry, so a platform the generator adds reaches the web admin channel through a schema
 * refresh instead of a code edit.
 *
 * <p>Two enums are read, each for the field it describes:
 * <ul>
 *   <li>{@code $defs.worklistEntry.properties.platform.enum} — a worklist ENTRY's platform, which
 *       is the batch entry's {@code hardwareClass};</li>
 *   <li>{@code $defs.imageConfig.properties.platform.enum} — the flat per-image ImageConfig's
 *       platform, which is an entry's {@code imageSpec.platform}.</li>
 * </ul>
 *
 * <p><b>Fail closed.</b> Loading happens once, at class initialisation. A missing or unreadable
 * resource, a missing or empty enum, a non-string member, or a member outside
 * {@link #TOKEN} throws, so the BFF does not start rather than accept a platform set it cannot
 * trust. The charset check matters because the entry platform is substituted into the per-build
 * manifest ({@code ImageBuildOrchestrator.renderManifest}); a schema refresh must never be able
 * to widen that value to arbitrary text.
 */
public final class GeneratorPlatforms {

    /** Classpath location of the vendored generator worklist schema. */
    public static final String SCHEMA_RESOURCE = "schema/worklist.v1.schema.json";

    /** Every platform must be a short lower-case token (letters, digits, inner hyphens). */
    static final Pattern TOKEN = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$");

    private static final Set<String> ENTRY;
    private static final Set<String> IMAGE_SPEC;

    static {
        JsonNode schema = load();
        ENTRY = readEnum(schema, "worklistEntry");
        IMAGE_SPEC = readEnum(schema, "imageConfig");
    }

    private GeneratorPlatforms() {
    }

    /** The platforms a worklist entry may name (a batch entry's {@code hardwareClass}). */
    public static Set<String> entryPlatforms() {
        return ENTRY;
    }

    /** The platforms a materialized {@code imageSpec} may name ({@code imageSpec.platform}). */
    public static Set<String> imageSpecPlatforms() {
        return IMAGE_SPEC;
    }

    public static boolean isEntryPlatform(String value) {
        return value != null && ENTRY.contains(value);
    }

    public static boolean isImageSpecPlatform(String value) {
        return value != null && IMAGE_SPEC.contains(value);
    }

    /** The entry platforms as a comma-separated list, in schema order, for refusal reasons. */
    public static String describeEntryPlatforms() {
        return String.join(", ", ENTRY);
    }

    /** The imageSpec platforms as a comma-separated list, in schema order, for refusal reasons. */
    public static String describeImageSpecPlatforms() {
        return String.join(", ", IMAGE_SPEC);
    }

    private static JsonNode load() {
        try (InputStream in = new ClassPathResource(SCHEMA_RESOURCE).getInputStream()) {
            JsonNode node = new ObjectMapper().readTree(in);
            if (node == null || !node.isObject()) {
                throw new IllegalStateException("worklist schema is not a JSON object: " + SCHEMA_RESOURCE);
            }
            return node;
        } catch (IOException e) {
            throw new IllegalStateException(
                    "worklist schema missing, unreadable or malformed: " + SCHEMA_RESOURCE, e);
        }
    }

    static Set<String> readEnum(JsonNode schema, String def) {
        String where = "$defs." + def + ".properties.platform.enum";
        JsonNode values = schema.path("$defs").path(def).path("properties").path("platform").path("enum");
        if (!values.isArray() || values.isEmpty()) {
            throw new IllegalStateException(SCHEMA_RESOURCE + ": " + where + " is missing or empty");
        }
        Set<String> out = new LinkedHashSet<>();
        for (JsonNode v : values) {
            if (!v.isTextual() || !TOKEN.matcher(v.asText()).matches()) {
                throw new IllegalStateException(
                        SCHEMA_RESOURCE + ": " + where + " member " + v + " is not a platform token");
            }
            out.add(v.asText());
        }
        // Schema order is kept so a refusal lists the platforms the way the generator does.
        return Collections.unmodifiableSet(out);
    }
}
