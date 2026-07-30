package systems.hugmesh.adminbff.imagegen;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.adminbff.web.dto.BatchImageSpec;
import systems.hugmesh.adminbff.web.dto.BatchTriggerImageBuildRequest;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The FAIL-CLOSED worklist.v1 ENVELOPE validator — the spec-injection gate that
 * {@link ImageBuildService#triggerBatch} MUST call BEFORE persisting any {@code image_spec_json}
 * or assembling any mesh manifest.
 *
 * <p><b>Why this exists (the security seam).</b> The renderManifest {@code yamlSafe()} guard
 * only fences the six SUBSTITUTED scalar values. The FULL {@code IMAGE_SPEC_JSON} channel writes
 * the {@code base}/{@code imageSpec} JSON straight into a per-build ConfigMap block-scalar,
 * BYPASSING {@code yamlSafe}. So the envelope content is fenced HERE instead, structurally:
 * <ul>
 *   <li>the {@code schema} discriminator is exact ({@code hugmesh-worklist/v1});</li>
 *   <li>{@code entries} is 1..{@value BatchTriggerImageBuildRequest#MAX_ENTRIES} (a HARD
 *       re-assert of the DTO {@code @Size}: one step-up authorizes at most this many images);</li>
 *   <li>every entry {@code platform} is one of the six generator platforms;</li>
 *   <li>NO plaintext {@code SECRET_FIELDS} ride the wire, in {@code base} OR any {@code imageSpec}
 *       (local_pass / luks_pass / user_password / root_password are ALWAYS blank);</li>
 *   <li>an {@code imageSpec} is a flat single-image object — it may NOT itself carry a nested
 *       {@code schema} key (no envelope-in-entry smuggling);</li>
 *   <li>every {@code packages_add}/{@code packages_drop} atom matches the Portage atom charset;</li>
 *   <li>every {@code base.domains[].name}, {@code base.users[].domain} and a non-blank
 *       {@code superdomain} is a syntactically-valid domain name (defence against a hostile
 *       label breaking out of the mesh manifest / MagicDNS channel).</li>
 * </ul>
 * A violation is a clean 400 ({@link ApiException#badRequest}); NOTHING is persisted or launched.
 * This is STRUCTURAL validation only — the AUTHZ own-domain wall on the same fields lives in the
 * service (a superadmin may reference cross-brand content; a hostile SYNTAX is refused for
 * everyone here).
 */
@Component
public class WorklistEnvelopeValidator {

    static final String SCHEMA = "hugmesh-worklist/v1";

    /** Plaintext secret fields that must ALWAYS be blank on the wire (never persisted / mounted). */
    static final Set<String> SECRET_FIELDS =
            Set.of("local_pass", "luks_pass", "user_password", "root_password");

    private static final Pattern PLATFORM =
            Pattern.compile("x86|rpi5|frite|jetson|orangepi5|orangepizero2");

    /** Portage atom charset (worklist.v1 schema packages_add/packages_drop). */
    private static final Pattern ATOM =
            Pattern.compile("^[a-z0-9][a-z0-9+._-]*/[A-Za-z0-9+._-]+$");

    /** A syntactically-valid DNS domain name (labels of alnum/hyphen, dot-separated), <=253. */
    private static final Pattern DOMAIN_NAME =
            Pattern.compile("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$");

    /**
     * Validate the whole envelope, throwing {@link ApiException#badRequest} on the first
     * violation. Idempotent + side-effect-free — safe to call before any write.
     */
    public void validate(BatchTriggerImageBuildRequest req) {
        if (req == null) {
            throw ApiException.badRequest("worklist envelope is required");
        }
        if (!SCHEMA.equals(req.schema())) {
            throw ApiException.badRequest("schema must be " + SCHEMA);
        }
        List<BatchImageSpec> entries = req.entries();
        if (entries == null || entries.isEmpty()) {
            throw ApiException.badRequest("at least one entry is required");
        }
        if (entries.size() > BatchTriggerImageBuildRequest.MAX_ENTRIES) {
            // HARD re-assert of the DTO @Size — one step-up authorizes at most MAX_ENTRIES images.
            throw ApiException.badRequest(
                    "a batch may build at most " + BatchTriggerImageBuildRequest.MAX_ENTRIES + " images");
        }

        // ── base (CONTENT) ────────────────────────────────────────────────────
        JsonNode base = req.base();
        if (base != null && !base.isNull()) {
            if (!base.isObject()) {
                throw ApiException.badRequest("worklist base must be an object");
            }
            assertNoSecrets(base, "base");
            assertDomainNames(base);
            assertPackageAtoms(base, "base");
            JsonNode sd = base.get("superdomain");
            if (sd != null && sd.isTextual() && !sd.asText().isBlank()
                    && !DOMAIN_NAME.matcher(sd.asText().trim()).matches()) {
                throw ApiException.badRequest("superdomain is not a valid domain name");
            }
        }

        // ── entries ───────────────────────────────────────────────────────────
        for (int i = 0; i < entries.size(); i++) {
            BatchImageSpec e = entries.get(i);
            if (e == null) {
                throw ApiException.badRequest("entry " + i + " is missing");
            }
            if (e.hardwareClass() == null || !PLATFORM.matcher(e.hardwareClass()).matches()) {
                throw ApiException.badRequest("entry " + i + " platform is not a supported generator platform");
            }
            JsonNode spec = e.imageSpec();
            if (spec != null && !spec.isNull()) {
                if (!spec.isObject()) {
                    throw ApiException.badRequest("entry " + i + " imageSpec must be an object");
                }
                if (spec.has("schema")) {
                    // A flat single-image spec must NOT itself be an envelope (no smuggling).
                    throw ApiException.badRequest("entry " + i + " imageSpec must not carry a nested schema");
                }
                assertNoSecrets(spec, "entry " + i + " imageSpec");
                assertPackageAtoms(spec, "entry " + i + " imageSpec");
                JsonNode p = spec.get("platform");
                if (p != null && p.isTextual() && !PLATFORM.matcher(p.asText()).matches()) {
                    throw ApiException.badRequest("entry " + i + " imageSpec platform is unsupported");
                }
            }
        }
    }

    /**
     * Every {@link #SECRET_FIELDS} key MUST be blank/absent ANYWHERE in the node tree —
     * recursively, through nested objects AND arrays, not just at the top level.
     *
     * <p>The whole {@code base}/{@code imageSpec} JSON is persisted as {@code image_spec_json}
     * and embedded verbatim into the per-build ConfigMap block-scalar the Job mounts. A shallow
     * top-level check let a secret nested one level down slip through into cleartext in etcd —
     * e.g. a per-user {@code user_password} on {@code base.users[]} (a nested shape this very
     * validator already walks in {@link #assertDomainNames}), or any secret inside an
     * {@code imageSpec}'s own {@code users[]}/{@code accounts[]}. The generator's own contract
     * blanks these at EVERY depth ({@code to_dict(include_secrets=False)}); enforce the same here.
     * (Recursing the {@code SECRET_FIELDS} denylist has no false positives — those four keys are
     * never legitimately non-blank on the wire. A stricter spec-key allowlist, which would also
     * reject an arbitrarily-mis-named injected key, is a possible future hardening.)
     */
    private void assertNoSecrets(JsonNode node, String where) {
        if (node == null || node.isNull()) {
            return;
        }
        if (node.isObject()) {
            for (String secret : SECRET_FIELDS) {
                JsonNode v = node.get(secret);
                if (v == null || v.isNull()) {
                    continue;
                }
                if (!v.isTextual()) {
                    // a non-string secret field (object/array/number) is itself anomalous.
                    throw ApiException.badRequest(
                            "secret field '" + secret + "' must be a blank string (" + where + ")");
                }
                if (!v.asText().isBlank()) {
                    throw ApiException.badRequest(
                            "plaintext secret '" + secret + "' must not ride the wire (" + where + ")");
                }
            }
            var fields = node.fields();
            while (fields.hasNext()) {
                var field = fields.next();
                if (field.getValue().isContainerNode()) {
                    assertNoSecrets(field.getValue(), where + "." + field.getKey());
                }
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                assertNoSecrets(node.get(i), where + "[" + i + "]");
            }
        }
    }

    /** Every {@code domains[].name} and {@code users[].domain} must be a valid domain name. */
    private void assertDomainNames(JsonNode base) {
        JsonNode domains = base.get("domains");
        if (domains != null && domains.isArray()) {
            for (JsonNode d : domains) {
                JsonNode name = d.get("name");
                if (name != null && name.isTextual() && !name.asText().isBlank()
                        && !DOMAIN_NAME.matcher(name.asText().trim()).matches()) {
                    throw ApiException.badRequest("base.domains[].name '" + name.asText() + "' is not a valid domain name");
                }
            }
        }
        JsonNode users = base.get("users");
        if (users != null && users.isArray()) {
            for (JsonNode u : users) {
                JsonNode dom = u.get("domain");
                if (dom != null && dom.isTextual() && !dom.asText().isBlank()
                        && !DOMAIN_NAME.matcher(dom.asText().trim()).matches()) {
                    throw ApiException.badRequest("base.users[].domain '" + dom.asText() + "' is not a valid domain name");
                }
            }
        }
    }

    /** Every packages_add / packages_drop atom (space-separated) must match the atom charset. */
    private void assertPackageAtoms(JsonNode node, String where) {
        assertAtomList(node.get("packages_add"), where + ".packages_add");
        assertAtomList(node.get("packages_drop"), where + ".packages_drop");
        // A worklist base may also carry per-image entries with the same fields — check nested
        // entries[] if a caller ever inlines them onto base (defence in depth; normally empty).
        JsonNode entries = node.get("entries");
        if (entries != null && entries.isArray()) {
            for (JsonNode e : entries) {
                assertAtomList(e.get("packages_add"), where + ".entries[].packages_add");
                assertAtomList(e.get("packages_drop"), where + ".entries[].packages_drop");
            }
        }
    }

    private void assertAtomList(JsonNode field, String where) {
        if (field == null || field.isNull()) {
            return;
        }
        if (!field.isTextual()) {
            throw ApiException.badRequest(where + " must be a space-separated atom string");
        }
        String raw = field.asText().trim();
        if (raw.isEmpty()) {
            return;
        }
        for (String atom : raw.split("\\s+")) {
            if (!ATOM.matcher(atom).matches()) {
                throw ApiException.badRequest(where + " atom '" + atom + "' is not a valid Portage atom");
            }
        }
    }
}
