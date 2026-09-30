package net.hugmesh.adminbff.web;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A 400 carrying a MAP of field refusals rather than one message — the same
 * {@code {"error":"validation failed","fields":{field:message}}} body a failed jakarta
 * constraint produces, raised from service code that validates something jakarta cannot
 * express.
 *
 * <p>Why this exists: {@link net.hugmesh.commons.web.ApiException} carries a single string, and
 * {@link ApiExceptionHandler} renders it as {@code {"error": msg}}. That is one line in the
 * console's form error. The app-profile schema (issue #55) reports EVERY violation at once,
 * path-keyed ({@code resources.cpu}, {@code roles[1]}, {@code exposure.ports[0]}), and the
 * console already folds a {@code fields} map into a per-field list
 * ({@code ServiceCatalogService.describeValidationFields}) — so the map shape reaches the
 * operator field by field with no UI change, and the one-line shape would throw that away.
 *
 * <p>Rendered by {@link ValidationExceptionHandler}, which owns that body shape.
 */
public class FieldValidationException extends RuntimeException {

    private final Map<String, String> fields;

    public FieldValidationException(Map<String, String> fields) {
        super("validation failed: " + fields);
        this.fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
    }

    /** Field path → message, in the order the violations were found. */
    public Map<String, String> fields() {
        return fields;
    }
}
