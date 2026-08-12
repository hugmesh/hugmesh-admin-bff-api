package net.hugmesh.adminbff.web;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import net.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reactive validation advice: turns a jakarta/Spring validation failure into a
 * clean {@code 400 Bad Request} with a structured field-error body. Two sources:
 *
 * <ul>
 *   <li>{@link WebExchangeBindException} — a {@code @Valid @RequestBody} DTO
 *       (web.dto.*) whose jakarta constraints failed.</li>
 *   <li>{@link ConstraintViolationException} — a {@code @Validated} controller's
 *       {@code @PathVariable}/{@code @RequestParam} constraint failure (e.g. the
 *       {@code pathPrefix} guard on {@code DELETE /bff/admin/routes/{pathPrefix}}).</li>
 * </ul>
 *
 * <p>The body shape is {@code {"error":"validation failed","fields":{field:msg}}}.
 * The {@code error} key matches the {@code {error}} convention the admin-ui/login-ui
 * read (see {@link ApiExceptionHandler}); {@code fields} is additive. This advice
 * handles exception types DISJOINT from {@link ApiExceptionHandler}, so the two
 * coexist — the controller's own {@link ApiException} (403/401/specific 400s) is
 * unaffected, preserving the reserved-name + invite-gate error messages.
 */
@RestControllerAdvice
public class ValidationExceptionHandler {

    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<Map<String, Object>> handleBind(WebExchangeBindException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (FieldError fe : ex.getFieldErrors()) {
            fields.putIfAbsent(fe.getField(),
                    fe.getDefaultMessage() == null ? "invalid" : fe.getDefaultMessage());
        }
        return badRequest(fields);
    }

    /**
     * Spring Framework 7 (Boot 4) routes {@code @Valid @RequestBody} DTO validation
     * through the UNIFIED method-validation path, surfacing a
     * {@link HandlerMethodValidationException} rather than a
     * {@link WebExchangeBindException} for the body argument. Unwrap its per-parameter
     * results: a {@code @Valid} bean parameter carries {@link FieldError}s (one per
     * failed component), so the {field:message} body shape is preserved unchanged.
     */
    @ExceptionHandler(HandlerMethodValidationException.class)
    public ResponseEntity<Map<String, Object>> handleMethodValidation(HandlerMethodValidationException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        // Accumulate field→message pairs from each per-parameter validation result.
        ex.getParameterValidationResults().forEach(result -> collectValidationErrors(result, fields));
        return badRequest(fields);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraint(ConstraintViolationException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (ConstraintViolation<?> v : ex.getConstraintViolations()) {
            String path = v.getPropertyPath() == null ? "" : v.getPropertyPath().toString();
            String leaf = path.contains(".") ? path.substring(path.lastIndexOf('.') + 1) : path;
            fields.putIfAbsent(leaf, v.getMessage());
        }
        return badRequest(fields);
    }

    /** Accumulate field→message entries from one per-parameter validation result into the map. */
    private static void collectValidationErrors(
            org.springframework.validation.method.ParameterValidationResult result,
            Map<String, String> fields) {
        List<? extends MessageSourceResolvable> errors = result.getResolvableErrors();
        for (MessageSourceResolvable error : errors) {
            if (error instanceof FieldError fe) {
                fields.putIfAbsent(fe.getField(),
                        fe.getDefaultMessage() == null ? "invalid" : fe.getDefaultMessage());
            } else {
                // @PathVariable/@RequestParam constraint: the method parameter is the leaf.
                String name = result.getMethodParameter().getParameterName();
                fields.putIfAbsent(name == null ? "request" : name,
                        error.getDefaultMessage() == null ? "invalid" : error.getDefaultMessage());
            }
        }
    }

    private static ResponseEntity<Map<String, Object>> badRequest(Map<String, String> fields) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "validation failed");
        body.put("fields", fields);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }
}
