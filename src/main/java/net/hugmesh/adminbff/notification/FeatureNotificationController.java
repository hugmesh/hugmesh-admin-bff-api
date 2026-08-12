package net.hugmesh.adminbff.notification;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;

import java.util.Map;

/**
 * ADMIN/SUPERADMIN trigger for FEATURE-AVAILABILITY + INFRA-IMPACTING notifications
 * (Notifications PR7). A platform change (a feature toggle, a planned maintenance event)
 * has no desired-state effect row to ride, so an admin explicitly emits the neutral
 * {@code @system} notification to an affected user via this endpoint; the existing
 * reconcilers fan it out.
 *
 * <h3>Authorization + tenancy (defence-in-depth)</h3>
 * Under {@code /bff/admin/**} ({@code hasAnyRole('ADMIN','SUPERADMIN')}); each method adds
 * {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")}. The {@code domain} is resolved
 * from the caller's CRYPTOGRAPHICALLY-VALIDATED JWT issuer via {@link PrincipalDomain} —
 * NEVER from the body — and is FAIL-CLOSED: an unresolved tenant ({@link PrincipalDomain#NO_DOMAIN})
 * is rejected (400) rather than silently writing to a default/other brand, with a dedicated
 * isolation test. The acting admin's identity is NEVER placed in the notification payload
 * (the {@code @system} sender is neutral).
 */
@Tag(name = "Notifications (feature/infra triggers)", description = "ADMIN/SUPERADMIN trigger "
        + "for feature-availability + infra-impacting @system notifications (domain from the "
        + "validated JWT, fail-closed; neutral sender, no actor in the payload).")
@RestController
@RequestMapping("/bff/admin/notifications")
@Validated
public class FeatureNotificationController {

    private static final Logger log = LoggerFactory.getLogger(FeatureNotificationController.class);

    private final FeatureNotificationService service;
    private final DomainRegistry domainRegistry;

    public FeatureNotificationController(FeatureNotificationService service, DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    /** The trigger body — the recipient + a stable event key + an optional neutral note.
     *  The DOMAIN is NOT in the body (it comes from the validated JWT). */
    public record TriggerRequest(
            @NotBlank @Size(max = 255) String recipientSubject,
            @NotBlank @Size(max = 200) String eventKey,
            @Size(max = 2048) String reason) {}

    @Operation(summary = "Emit a feature-availability @system notification to a user "
            + "(ADMIN/SUPERADMIN; domain from the validated JWT, fail-closed).", operationId = "featureNotificationFeatureAvailability")
    @PostMapping("/feature-availability")
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    public Mono<Map<String, Object>> featureAvailability(@RequestBody @Valid TriggerRequest body,
                                                         Authentication auth) {
        return emit(FeatureNotificationService.Kind.FEATURE_AVAILABILITY, body, auth);
    }

    @Operation(summary = "Emit an infra-impacting @system notification to a user "
            + "(ADMIN/SUPERADMIN; domain from the validated JWT, fail-closed).", operationId = "featureNotificationInfraImpacting")
    @PostMapping("/infra-impacting")
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    public Mono<Map<String, Object>> infraImpacting(@RequestBody @Valid TriggerRequest body,
                                                     Authentication auth) {
        return emit(FeatureNotificationService.Kind.INFRA_IMPACTING, body, auth);
    }

    private Mono<Map<String, Object>> emit(FeatureNotificationService.Kind kind,
                                           TriggerRequest body, Authentication auth) {
        String domain = PrincipalDomain.of(auth, domainRegistry).domain();
        if (domain == null || PrincipalDomain.NO_DOMAIN.equals(domain)) {
            // FAIL-CLOSED: never emit for an unresolvable tenant (no silent default brand).
            return Mono.error(ApiException.badRequest("caller tenant could not be resolved"));
        }
        return service.emit(kind, domain, body.recipientSubject(), body.eventKey(), body.reason())
                .map(inserted -> Map.<String, Object>of(
                        "domain", domain,
                        "category", kind == FeatureNotificationService.Kind.FEATURE_AVAILABILITY
                                ? NotificationOutbox.CATEGORY_FEATURE_AVAILABILITY
                                : NotificationOutbox.CATEGORY_INFRA_IMPACTING,
                        "recipientSubject", body.recipientSubject(),
                        "emitted", inserted))
                .doOnSuccess(r -> log.info("[notify-trigger] {} emitted for domain={} recipient={} -> {}",
                        kind, domain, body.recipientSubject(), r.get("emitted")));
    }
}
