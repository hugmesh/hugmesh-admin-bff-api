package net.hugmesh.adminbff.web;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import net.hugmesh.commons.web.ApiException;

import java.util.Map;

/**
 * Renders {@link ApiException} as the {@code {"error": message}} JSON body (and
 * the carried status) the UIs read — they do
 * {@code (await r.json().catch(()=>({}))).error || 'HTTP <status>'}, so the shape
 * must be {@code {error}} exactly as in the reference impl (mock-bff.mjs). Works
 * unchanged under WebFlux: {@code @RestControllerAdvice} + {@code @ExceptionHandler}
 * returning a {@code ResponseEntity} is handled reactively (the controller's
 * {@code Mono.error(ApiException)} is routed here).
 *
 * <p><b>Step-up signal.</b> This is ALSO the single seam that stamps the structured
 * step-up signal: a {@link StepUpRequiredException} additionally carries the
 * {@value StepUpRequiredException#SIGNAL_HEADER} response header naming the retry header
 * the client must present its step-up token in. The JSON body is left byte-identical —
 * nothing is added to the shared error body, so no unrelated error's wire shape moves —
 * and the status stays whatever the exception carries (403 for step-up; deliberately not
 * 428, every existing client branches on 403). Any OTHER {@link ApiException}, including
 * an ordinary authz 403, is rendered exactly as before with NO signal header, which is
 * what keeps a routine DENY from popping an MFA prompt in the browser.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handle(ApiException ex) {
        ResponseEntity.BodyBuilder response = ResponseEntity.status(ex.status());
        if (ex instanceof StepUpRequiredException stepUp) {
            response = response.header(StepUpRequiredException.SIGNAL_HEADER,
                    stepUp.retryHeader());
        }
        return response.body(Map.of("error", ex.getMessage()));
    }
}
