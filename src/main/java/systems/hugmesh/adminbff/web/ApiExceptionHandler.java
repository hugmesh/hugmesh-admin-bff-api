package systems.hugmesh.adminbff.web;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import systems.hugmesh.commons.web.ApiException;

import java.util.Map;

/**
 * Renders {@link ApiException} as the {@code {"error": message}} JSON body (and
 * the carried status) the UIs read — they do
 * {@code (await r.json().catch(()=>({}))).error || 'HTTP <status>'}, so the shape
 * must be {@code {error}} exactly as in the reference impl (mock-bff.mjs). Works
 * unchanged under WebFlux: {@code @RestControllerAdvice} + {@code @ExceptionHandler}
 * returning a {@code ResponseEntity} is handled reactively (the controller's
 * {@code Mono.error(ApiException)} is routed here).
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handle(ApiException ex) {
        return ResponseEntity.status(ex.status()).body(Map.of("error", ex.getMessage()));
    }
}
