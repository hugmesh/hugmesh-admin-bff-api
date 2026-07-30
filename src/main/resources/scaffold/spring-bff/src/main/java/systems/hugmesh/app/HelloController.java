package systems.hugmesh.{{APP_SLUG}};

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * The one example endpoint: {@code GET /api/{{APP_SLUG}}/hello} returns
 * {@code {service, message}}. It sits under {@code /api/**} (the gateway-routed
 * API surface) and is AUTHENTICATED by {@link SecurityConfig} — only the
 * actuator health probes are public. The service name is read from
 * {@code spring.application.name} so the payload always reports this repo's own
 * identity, not a copy-paste literal.
 */
@RestController
@RequestMapping("/api/{{APP_SLUG}}")
public class HelloController {

    private final String serviceName;

    public HelloController(@Value("${spring.application.name}") String serviceName) {
        this.serviceName = serviceName;
    }

    @GetMapping("/hello")
    public Mono<Map<String, String>> hello() {
        return Mono.just(Map.of(
                "service", serviceName,
                "message", "Hello from " + serviceName));
    }
}
