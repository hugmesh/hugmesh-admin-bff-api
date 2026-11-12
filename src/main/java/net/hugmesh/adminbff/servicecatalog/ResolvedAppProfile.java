package net.hugmesh.adminbff.servicecatalog;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.hugmesh.commons.web.ApiException;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;

/**
 * The TYPED reading of an {@code app_profile.profile_json} document (the shape
 * {@code schema/app-profile.schema.json} defines) — what {@link AddServiceEffector} resolves a
 * {@link ServiceDeployment#profileRef()} into before it provisions (catalog-ui#3, first slice).
 *
 * <h3>Consumed vs recorded-only</h3>
 * The effector APPLIES the parts it already owns:
 * <ul>
 *   <li>{@link #routes()} ({@code exposure.routes}) — extra route-access url_patterns beside the
 *       derived {@code /api/<service>/};</li>
 *   <li>{@link #roles()} ({@code roles[]}) — extra {@code ROLE_<UPPER>} grants on every one of
 *       those patterns, beside the derived per-service role;</li>
 *   <li>{@link #mfaRequired()} ({@code exposure.mfaRequired}) — {@code mfa_required} on every rule
 *       the provision writes.</li>
 * </ul>
 * Everything else ({@code resources.cpu/memory}, {@code certs.altNames/ttl},
 * {@code exposure.ports}) is parsed and carried here but NOT consumed: there is no ArgoCD
 * parameter channel or ExternalSecret parameter channel the effector could hand them to yet, so
 * {@link #recordedOnly()} lists them for a log line and nothing else reads them.
 *
 * <h3>Fail closed on a body that does not match the schema</h3>
 * {@code profile_json} is schema-checked on SAVE, but reads are deliberately not validated, so a
 * row written before the schema existed (the flat {@code {"cpu","memory"}} form) can still be
 * loaded. Resolving such a body would silently yield an EMPTY profile — the deployment would be
 * provisioned without the grants or MFA requirement its operator asked for. {@link #parse} re-runs
 * {@link AppProfileSchema#validate} first and refuses (422) instead.
 */
public record ResolvedAppProfile(
        String name,
        List<String> routes,
        List<String> roles,
        boolean mfaRequired,
        @Nullable String cpu,
        @Nullable String memory,
        List<String> certAltNames,
        @Nullable String certTtl,
        List<Integer> ports) {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** The profile a deployment with NO {@code profileRef} resolves to: no extra routes, no extra
     *  roles, MFA not required — i.e. exactly the derived rule the effector wrote before profiles
     *  were resolved. */
    public static final ResolvedAppProfile NONE =
            new ResolvedAppProfile(null, List.of(), List.of(), false, null, null, List.of(), null, List.of());

    public ResolvedAppProfile {
        routes = List.copyOf(routes);
        roles = List.copyOf(roles);
        certAltNames = List.copyOf(certAltNames);
        ports = List.copyOf(ports);
    }

    /**
     * Parse a stored {@code profile_json}. Refuses (422) a body the schema refuses, naming the
     * profile and every offending field, so the operator knows which template to fix.
     */
    public static ResolvedAppProfile parse(String name, String profileJson) {
        List<AppProfileSchema.FieldError> errors = AppProfileSchema.validate(profileJson);
        if (!errors.isEmpty()) {
            throw ApiException.unprocessable("app_profile '" + name + "' does not match the app-profile"
                    + " schema and cannot be resolved for provisioning: "
                    + AppProfileSchema.asFields(errors)
                    + " - edit it in the Service Catalog console, then provision again");
        }
        JsonNode root;
        try {
            root = JSON.readTree(profileJson);
        } catch (JsonProcessingException e) {
            // Unreachable after validate() (it parses the same text), kept as a closed failure.
            throw ApiException.unprocessable("app_profile '" + name + "' is not valid JSON");
        }
        JsonNode resources = root.path("resources");
        JsonNode certs = root.path("certs");
        JsonNode exposure = root.path("exposure");
        return new ResolvedAppProfile(
                name,
                strings(exposure.path("routes")),
                strings(root.path("roles")),
                exposure.path("mfaRequired").asBoolean(false),
                text(resources.path("cpu")),
                text(resources.path("memory")),
                strings(certs.path("altNames")),
                text(certs.path("ttl")),
                ints(exposure.path("ports")));
    }

    /** True for the no-profile sentinel. */
    public boolean isNone() {
        return name == null;
    }

    /** Human-readable list of the parsed-but-NOT-consumed fields that are set, for the effector's
     *  "recorded only" log line; empty when the profile sets none of them. */
    public List<String> recordedOnly() {
        List<String> out = new ArrayList<>();
        if (cpu != null) {
            out.add("resources.cpu=" + cpu);
        }
        if (memory != null) {
            out.add("resources.memory=" + memory);
        }
        if (!certAltNames.isEmpty()) {
            out.add("certs.altNames=" + certAltNames);
        }
        if (certTtl != null) {
            out.add("certs.ttl=" + certTtl);
        }
        if (!ports.isEmpty()) {
            out.add("exposure.ports=" + ports);
        }
        return out;
    }

    private static @Nullable String text(JsonNode n) {
        return n.isTextual() ? n.asText() : null;
    }

    private static List<String> strings(JsonNode n) {
        List<String> out = new ArrayList<>();
        if (n.isArray()) {
            n.forEach(e -> out.add(e.asText()));
        }
        return out;
    }

    private static List<Integer> ints(JsonNode n) {
        List<Integer> out = new ArrayList<>();
        if (n.isArray()) {
            n.forEach(e -> out.add(e.asInt()));
        }
        return out;
    }
}
