package net.hugmesh.adminbff.servicecatalog;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.web.dto.AppProfileRequest;

/**
 * The SUPERADMIN App-Store APP-PROFILE console — superadmin CRUD over the reusable deploy
 * templates ({@code app_profile}, schema 101). Profiles are a GLOBAL, cross-domain library
 * (no per-row tenant scope); a deployment references one by {@code name}.
 *
 * <h3>Authorization — SUPERADMIN-ONLY (defence-in-depth)</h3>
 * Mounted under {@code /bff/superadmin/**} (coarse gate {@code hasRole('SUPERADMIN')} in
 * {@link net.hugmesh.adminbff.config.SecurityConfig}); EVERY method ALSO carries
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")}. ADMIN / MOD / USER → 403.
 * {@code created_by_subject} is stamped from the SUPERADMIN's {@code jwt.getSubject()}.
 */
@RestController
@RequestMapping("/bff/superadmin/app-profiles")
@Validated
public class AppProfileController {

    private final AppProfileService service;

    public AppProfileController(AppProfileService service) {
        this.service = service;
    }

    /** The Casdoor subject of the acting SUPERADMIN, from the validated JWT. */
    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "List", operationId = "appProfileList")
    @GetMapping
    public Flux<AppProfile> list() {
        return service.list();
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Get", operationId = "appProfileGet")
    @GetMapping("/{name}")
    public Mono<AppProfile> get(@PathVariable @NotBlank @Size(max = 128) String name) {
        return service.get(name);
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Create", operationId = "appProfileCreate")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<AppProfile> create(@Valid @RequestBody AppProfileRequest body, Authentication auth) {
        return service.create(body.name(), body.profileJson(), subject(auth));
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Update", operationId = "appProfileUpdate")
    @PutMapping("/{name}")
    public Mono<AppProfile> update(
            @PathVariable @NotBlank @Size(max = 128) String name,
            @Valid @RequestBody AppProfileRequest body) {
        return service.update(name, body.profileJson());
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Delete", operationId = "appProfileDelete")
    @DeleteMapping("/{name}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> delete(@PathVariable @NotBlank @Size(max = 128) String name) {
        return service.delete(name);
    }
}
