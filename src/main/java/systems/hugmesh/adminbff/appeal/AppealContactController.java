package systems.hugmesh.adminbff.appeal;

import io.swagger.v3.oas.annotations.Operation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * PUBLIC (unauthenticated) appeal-contact resolver — mirrors the hugmesh.games
 * {@code AppealContactController} pattern. A banned / logged-out principal (the host
 * appeal-gate shows them this after reading {@code status:"banned"} from
 * {@code /bff/me} or the login response) needs a real {@code mailto:} address to
 * appeal to — NOT a POST into a void. This endpoint returns ONLY a contact email
 * from config so the UI can render the mailto.
 *
 * <p>It is {@code permitAll} at the resource-server filter chain (declared in
 * {@link systems.hugmesh.adminbff.config.SecurityConfig} BEFORE the authenticated
 * catch-all, alongside the existing {@code /bff/public/announcements/login}) because
 * the very principal who needs it has no usable session. It is reachable under
 * {@code /bff/public/**}, which the gateway also marks PUBLIC.
 *
 * <p>It deliberately exposes ONLY the email string — no admin/mod identity, nothing
 * usable for targeted phishing or reconnaissance. The address is a single config
 * value ({@code app.appeal.contact-email}, default {@code appeals@hugmesh.systems});
 * a deployment overrides it per brand.
 */
@RestController
public class AppealContactController {

    private final String contactEmail;

    public AppealContactController(
            @Value("${app.appeal.contact-email:appeals@hugmesh.systems}") String contactEmail) {
        this.contactEmail = contactEmail;
    }

    /** {@code GET /bff/public/appeal-contact} → {@code {"email":"<address>"}}. */
    @Operation(summary = "Appeal contact", operationId = "appealContactAppealContact")
    @GetMapping("/bff/public/appeal-contact")
    public Mono<Map<String, String>> appealContact() {
        return Mono.just(Map.of("email", contactEmail));
    }
}
