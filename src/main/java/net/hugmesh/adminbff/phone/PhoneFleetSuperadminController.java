package net.hugmesh.adminbff.phone;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The SUPERADMIN read side of the MDM phone registry — the queryable fleet view over the
 * {@code phone_device} rows the {@link PhoneIngestController} ingest channel writes.
 *
 * <h3>Authorization — SUPERADMIN-ONLY, CROSS-DOMAIN (defence-in-depth)</h3>
 * The coarse path gate ({@code SecurityConfig.commonRoutes}) on {@code /bff/superadmin/**}
 * is {@code hasRole('SUPERADMIN')}; EVERY endpoint here ALSO adds
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")}. Phones are onboarded by the MDM operator
 * tooling (Headwind + phone-wizard, a superadmin/devops posture — the same trust plane as
 * the Headwind console itself), so the fleet view is deliberately superadmin-only and NOT
 * per-domain scoped: a record's {@code attachedDomain} is telemetry the superadmin reads,
 * not a tenancy wall. Reads only — the registry has no mutation surface here (rows are
 * written solely by the ingest channel; there is no delete, the inventory is the audit
 * trail).
 */
@RestController
@RequestMapping("/bff/superadmin/phone-devices")
@Validated
public class PhoneFleetSuperadminController {

    private final PhoneDeviceService service;

    public PhoneFleetSuperadminController(PhoneDeviceService service) {
        this.service = service;
    }

    /**
     * The whole phone fleet, newest ingest activity first: {@code {"phones":[...]}}.
     * Unpaginated by the established device-list idiom (DeviceLicenseController et al.) —
     * an MDM phone fleet is operator-onboarded one handset at a time, so the row count
     * stays administrative-scale; revisit alongside the other device lists if pagination
     * ever arrives.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List phone fleet", operationId = "phoneFleetSuperadminList")
    @GetMapping("")
    public Mono<Map<String, Object>> list() {
        return service.list().collectList().map(phones -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("phones", phones);
            return out;
        });
    }

    /** One registry record by its onboarding-stable device id; 404 when unknown. The
     *  variable carries the same bounds as the ingest DTO's device_id (class-level
     *  {@code @Validated} enforces them → 400, not an unbounded string into the query). */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Get phone", operationId = "phoneFleetSuperadminGet")
    @GetMapping("/{deviceId}")
    public Mono<PhoneDevice> get(@PathVariable @NotBlank @Size(max = 128) String deviceId) {
        return service.find(deviceId)
                .switchIfEmpty(Mono.error(
                        ApiException.notFound("phone '" + deviceId + "' not found")));
    }
}
