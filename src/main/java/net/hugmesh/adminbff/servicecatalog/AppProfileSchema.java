package net.hugmesh.adminbff.servicecatalog;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The SERVER half of the app-profile schema contract (issue #55; the sibling of
 * hugmesh-superadmin-service-catalog-ui#3). Validates the {@code profileJson} body of an
 * {@code app_profile} row against the committed JSON Schema before it is stored.
 *
 * <h3>Why this is a hand-written interpreter and not a JSON-Schema library</h3>
 * The contract is not "be a correct JSON Schema validator" — it is "refuse EXACTLY what the
 * console refuses, with EXACTLY the same message". The console
 * ({@code src/app/app-profile-schema.ts}) is itself a small interpreter over the same subset,
 * and its messages are the operator-facing vocabulary
 * ({@code unknown field (allowed here: …)}, {@code must be at most N character(s)}, …).
 * A general validator would agree on the verdict and disagree on every string, and the
 * operator would see a different refusal depending on which half caught it. So this class
 * mirrors that file, keyword for keyword and message for message.
 *
 * <h3>The schema FILE is the contract, and it is byte-identical on both sides</h3>
 * {@code src/main/resources/schema/app-profile.schema.json} is a byte-for-byte copy of
 * {@code schemas/app-profile.schema.json} in the console repo. {@link AppProfileSchemaMirrorTest}
 * here and {@code scripts/assert-schema-pin.mjs} there guard that, and it is worth knowing how:
 * the matching sha256 LITERALS only make an edit deliberate within one repo (moving the file and
 * the literal together satisfies both repos' literals while the two files diverge — that was
 * measured, both suites green), so each side also READS the other repo's file and compares bytes
 * whenever that checkout is reachable, which CI guarantees by cloning it. The byte comparison is
 * the half that enforces the contract. Loosening the schema loosens both halves together, which
 * is the whole point of the copy.
 *
 * <h3>Anchoring — the one place a byte-identical copy is NOT enough</h3>
 * JSON Schema defines {@code pattern} as a PARTIAL match, and {@code java.util.regex}
 * additionally lets {@code $} match before a final line terminator. Measured on Temurin
 * 25.0.4.1 with the {@code resources.cpu} pattern:
 * {@code Pattern.compile(p).matcher("500m\n").find()} is {@code true} while the browser's
 * {@code new RegExp(p,"u").test("500m\n")} is {@code false}. An ordinary
 * {@code find()}-based validator over a byte-identical schema therefore ACCEPTS bodies the
 * console REFUSES — the exact drift the copy exists to stop. Every pattern here is applied
 * with {@link Matcher#matches()}, which requires the whole value. The committed schema file
 * carries the same warning as a root {@code $comment}.
 *
 * <h3>Fail CLOSED on a schema this interpreter cannot enforce</h3>
 * Two shapes would silently accept anything: a subschema with no {@code type} (every branch
 * below is gated on it) and an {@code additionalProperties} that is not a boolean. Both are
 * reported as {@code schema error: …} refusals rather than skipped. The committed file trips
 * neither, and a test walks it to keep that true.
 *
 * <p>Thread-safe and stateless: the parsed schema and the compiled patterns are immutable and
 * shared.
 */
public final class AppProfileSchema {

    /** Classpath location of the byte-identical copy of the console's schema file. */
    public static final String RESOURCE = "schema/app-profile.schema.json";

    /** The JSON Schema type names this interpreter understands. Mirrors {@code TYPES}. */
    private static final Set<String> TYPES =
            Set.of("object", "array", "string", "integer", "number", "boolean");

    /**
     * The subset of JSON Schema this interpreter implements, mirroring
     * {@code SUPPORTED_KEYWORDS} in the console. A keyword NOT listed here is one the
     * interpreter would silently skip — i.e. fail OPEN — so a test walks the committed schema
     * and fails the moment an unlisted keyword appears in it.
     */
    public static final Set<String> SUPPORTED_KEYWORDS = Set.of(
            // annotations (no validation effect; `examples` feeds the hint in a pattern error)
            "$schema", "$id", "$comment", "title", "description", "examples",
            // object
            "type", "properties", "additionalProperties", "required",
            // string
            "pattern", "minLength", "maxLength",
            // array
            "items", "uniqueItems", "minItems", "maxItems",
            // number / integer
            "minimum", "maximum");

    /** Parses request bodies. STRICT_DUPLICATE_DETECTION is deliberate — see {@link #validate}. */
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

    /** The committed schema, parsed once. */
    private static final JsonNode SCHEMA = load();

    /** Compiled {@code pattern} cache — compiling per value would be wasteful and identical. */
    private static final Map<String, Pattern> PATTERNS = new java.util.concurrent.ConcurrentHashMap<>();

    private AppProfileSchema() {
    }

    /** The committed schema as a node, for the tests that walk it. */
    public static JsonNode schema() {
        return SCHEMA;
    }

    /** The raw bytes of the committed schema copy, for the sha256 mirror pin. */
    public static byte[] resourceBytes() {
        try (InputStream in = new ClassPathResource(RESOURCE).getInputStream()) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException("cannot read " + RESOURCE, e);
        }
    }

    private static JsonNode load() {
        try {
            return new ObjectMapper().readTree(new String(resourceBytes(), StandardCharsets.UTF_8));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(RESOURCE + " is not valid JSON", e);
        }
    }

    /** One field-level refusal: {@code path} dotted from the root ({@code $} for the root). */
    public record FieldError(String path, String message) {
    }

    /**
     * Validate a stored/submitted {@code profileJson} body against the committed schema.
     *
     * <ul>
     *   <li>{@code null} or blank is the minimal valid profile {@code {}} — the console sends
     *       blank text as {@code {}} and the column is nullable, so both halves agree.</li>
     *   <li>Text that does not parse is ONE error at {@code $}: {@code not valid JSON (…)}.
     *       A DUPLICATE KEY lands here too, and that is the point: {@code JSON.parse} in the
     *       browser is last-wins and cannot refuse one, so the server is the only half that
     *       can decide it, and refusing is the safe choice.</li>
     *   <li>A root that is not a JSON OBJECT (array/string/number/boolean/null) is refused at
     *       {@code $} with {@code must be an object}.</li>
     *   <li>Otherwise EVERY schema violation is returned, not just the first, so the operator
     *       fixes a template in one pass.</li>
     * </ul>
     *
     * @return an empty list when the body is valid.
     */
    public static List<FieldError> validate(String profileJson) {
        return validateAgainst(SCHEMA, profileJson);
    }

    /**
     * {@link #validate} against an ARBITRARY subschema. Package-private so the tests can drive the
     * interpreter with a PROBE schema and prove the fail-CLOSED paths — a node with no
     * {@code type}, an unsupported {@code type}, a non-boolean {@code additionalProperties} — really
     * do refuse rather than skip. The committed file trips none of them, so nothing in production
     * calls this with anything but the committed schema. Mirrors {@code validateAgainstSchema} in
     * the console, which is exported for exactly the same reason.
     */
    static List<FieldError> validateAgainst(JsonNode schema, String profileJson) {
        String text = profileJson == null ? "" : profileJson.trim();
        JsonNode parsed;
        if (text.isEmpty()) {
            parsed = MAPPER.createObjectNode();
        } else {
            try {
                parsed = MAPPER.readTree(text);
            } catch (JsonProcessingException e) {
                return List.of(new FieldError("$", "not valid JSON (" + reason(e) + ")"));
            }
            if (parsed == null || parsed.isMissingNode()) {
                return List.of(new FieldError("$", "not valid JSON (no content)"));
            }
        }
        List<FieldError> errors = new ArrayList<>();
        check(parsed, schema, "$", errors);
        return errors;
    }

    /**
     * Fold refusals into the {@code fields} map of the shared 400 body
     * ({@code {"error":"validation failed","fields":{path:message}}}). Insertion order is
     * preserved, and the rare case of two refusals at the SAME path (an array that is both too
     * long and has a duplicate, say) is joined with {@code "; "} so nothing is dropped —
     * "all errors at once" is part of the contract.
     */
    public static Map<String, String> asFields(List<FieldError> errors) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (FieldError e : errors) {
            fields.merge(e.path(), e.message(), (a, b) -> a + "; " + b);
        }
        return fields;
    }

    /** Jackson's parse message without its {@code at [Source: …]} location tail. */
    private static String reason(JsonProcessingException e) {
        String msg = e.getOriginalMessage();
        if (msg == null) {
            msg = String.valueOf(e.getMessage());
        }
        int at = msg.indexOf("\n at [Source");
        return at >= 0 ? msg.substring(0, at) : msg;
    }

    private static String child(String path, String key) {
        return "$".equals(path) ? key : path + "." + key;
    }

    private static String item(String path, int index) {
        return "$".equals(path) ? "[" + index + "]" : path + "[" + index + "]";
    }

    private static boolean isType(JsonNode value, String type) {
        return switch (type) {
            case "object" -> value.isObject();
            case "array" -> value.isArray();
            case "string" -> value.isTextual();
            // "a JSON number with no fractional part" — 1.0 IS an integer, matching
            // Number.isInteger(1.0) === true in the console.
            case "integer" -> value.isNumber() && integral(value);
            case "number" -> value.isNumber();
            case "boolean" -> value.isBoolean();
            default -> false;
        };
    }

    private static boolean integral(JsonNode value) {
        if (value.isIntegralNumber()) {
            return true;
        }
        if (value.isDouble() || value.isFloat()) {
            double d = value.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                return false;
            }
        }
        BigDecimal dec = value.decimalValue();
        return dec.stripTrailingZeros().scale() <= 0;
    }

    private static String article(String type) {
        return ("object".equals(type) || "array".equals(type) || "integer".equals(type))
                ? "an " + type : "a " + type;
    }

    /** {@code " (e.g. \"500m\", \"1\")"} — the schema's own {@code examples}, JSON-encoded. */
    private static String hint(JsonNode schema) {
        JsonNode examples = schema.get("examples");
        if (examples == null || !examples.isArray() || examples.size() == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(" (e.g. ");
        for (int i = 0; i < examples.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(examples.get(i).toString());
        }
        return sb.append(')').toString();
    }

    /**
     * Identity used by {@code uniqueItems}, mirroring the console's {@code JSON.stringify(v)}.
     * Numbers are normalised so {@code 1} and {@code 1.0} collide exactly as they do in the
     * browser (where both are the same double). Exotic float spellings — {@code 1e21} and the
     * like — are NOT rendered the way ECMA-262 renders them; that is unreachable through the
     * committed schema, whose only arrays hold strings and integers, and is noted rather than
     * hidden.
     */
    private static String canonical(JsonNode value) {
        if (value.isNumber() && integral(value)) {
            return value.decimalValue().stripTrailingZeros().toBigInteger().toString();
        }
        return value.toString();
    }

    private static Pattern pattern(String regex) {
        return PATTERNS.computeIfAbsent(regex, Pattern::compile);
    }

    private static void check(JsonNode value, JsonNode schema, String path, List<FieldError> errors) {
        JsonNode typeNode = schema.get("type");
        if (typeNode == null || !typeNode.isTextual()) {
            // Fail CLOSED. Every branch below is gated on `type`, so a subschema without one
            // would have ALL of its keywords skipped and accept any value.
            errors.add(new FieldError(path, "schema error: subschema declares no \"type\""));
            return;
        }
        String type = typeNode.textValue();
        if (!TYPES.contains(type)) {
            errors.add(new FieldError(path, "schema error: unsupported type \"" + type + "\""));
            return;
        }
        if (!isType(value, type)) {
            errors.add(new FieldError(path, "must be " + article(type)));
            return;
        }

        switch (type) {
            case "object" -> checkObject((ObjectNode) value, schema, path, errors);
            case "array" -> checkArray(value, schema, path, errors);
            case "string" -> checkString(value.textValue(), schema, path, errors);
            case "integer", "number" -> checkNumber(value, schema, path, errors);
            default -> { /* boolean carries no further keyword in this subset */ }
        }
    }

    private static void checkObject(ObjectNode obj, JsonNode schema, String path, List<FieldError> errors) {
        JsonNode props = schema.get("properties");
        JsonNode additional = schema.get("additionalProperties");
        if (additional != null && !additional.isBoolean()) {
            // A schema-object additionalProperties is a form this interpreter does not
            // implement; treating it as "open" would accept every unknown key silently.
            errors.add(new FieldError(path,
                    "schema error: unsupported additionalProperties (must be a boolean)"));
            return;
        }
        boolean closed = additional != null && !additional.booleanValue();
        JsonNode required = schema.get("required");
        if (required != null && required.isArray()) {
            for (JsonNode req : required) {
                if (!obj.has(req.asText())) {
                    errors.add(new FieldError(child(path, req.asText()), "is required"));
                }
            }
        }
        Iterator<String> keys = obj.fieldNames();
        while (keys.hasNext()) {
            String key = keys.next();
            JsonNode sub = props == null ? null : props.get(key);
            if (sub == null) {
                if (closed) {
                    errors.add(new FieldError(child(path, key),
                            "unknown field (allowed here: " + allowed(props) + ")"));
                }
                continue;
            }
            check(obj.get(key), sub, child(path, key), errors);
        }
    }

    private static String allowed(JsonNode props) {
        if (props == null || props.size() == 0) {
            return "none";
        }
        Set<String> names = new LinkedHashSet<>();
        props.fieldNames().forEachRemaining(names::add);
        return String.join(", ", names);
    }

    private static void checkArray(JsonNode arr, JsonNode schema, String path, List<FieldError> errors) {
        JsonNode minItems = schema.get("minItems");
        if (minItems != null && arr.size() < minItems.intValue()) {
            errors.add(new FieldError(path, "must have at least " + minItems.asText() + " item(s)"));
        }
        JsonNode maxItems = schema.get("maxItems");
        if (maxItems != null && arr.size() > maxItems.intValue()) {
            errors.add(new FieldError(path, "must have at most " + maxItems.asText() + " item(s)"));
        }
        JsonNode unique = schema.get("uniqueItems");
        if (unique != null && unique.booleanValue()) {
            Set<String> seen = new LinkedHashSet<>();
            for (int i = 0; i < arr.size(); i++) {
                if (!seen.add(canonical(arr.get(i)))) {
                    errors.add(new FieldError(item(path, i), "duplicates an earlier item"));
                }
            }
        }
        JsonNode items = schema.get("items");
        if (items != null) {
            for (int i = 0; i < arr.size(); i++) {
                check(arr.get(i), items, item(path, i), errors);
            }
        }
    }

    private static void checkString(String s, JsonNode schema, String path, List<FieldError> errors) {
        JsonNode minLength = schema.get("minLength");
        if (minLength != null && s.length() < minLength.intValue()) {
            errors.add(new FieldError(path, "must be at least " + minLength.asText() + " character(s)"));
        }
        JsonNode maxLength = schema.get("maxLength");
        if (maxLength != null && s.length() > maxLength.intValue()) {
            errors.add(new FieldError(path, "must be at most " + maxLength.asText() + " character(s)"));
        }
        JsonNode regex = schema.get("pattern");
        // matches(), NEVER find() — see the anchoring note in this class's javadoc.
        if (regex != null && !pattern(regex.textValue()).matcher(s).matches()) {
            errors.add(new FieldError(path, "must match " + regex.textValue() + hint(schema)));
        }
    }

    private static void checkNumber(JsonNode value, JsonNode schema, String path, List<FieldError> errors) {
        BigDecimal n = value.decimalValue();
        JsonNode min = schema.get("minimum");
        if (min != null && n.compareTo(min.decimalValue()) < 0) {
            errors.add(new FieldError(path, "must be at least " + min.asText()));
        }
        JsonNode max = schema.get("maximum");
        if (max != null && n.compareTo(max.decimalValue()) > 0) {
            errors.add(new FieldError(path, "must be at most " + max.asText()));
        }
    }
}
