package net.hugmesh.adminbff.gamesservices;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.web.dto.CreateGameInstanceRequest;
import net.hugmesh.adminbff.web.dto.GameInstanceConnectionResponse;
import net.hugmesh.adminbff.web.dto.GameInstanceResponse;

/**
 * The GAMES APP-STORE per-domain INSTANCE console — create/run/stop game-server instances
 * (the games-services control plane, PR6) at {@code /bff/games-services/instances}.
 *
 * <h3>Authorization — the AND-derived-role model + the PrincipalDomain boundary</h3>
 * The coarse path gate ({@code SecurityConfig.commonRoutes}) on
 * {@code /bff/games-services/**} is {@code hasAnyRole(GAMES_SERVICES, ..._ADMIN, ..._RUNNER)};
 * each method then narrows:
 * <ul>
 *   <li>{@code list}/{@code get} — {@code GAMES_SERVICES} (any games-services member sees
 *       their OWN brand's instances; PrincipalDomain scopes the rows).</li>
 *   <li>{@code create} — {@code GAMES_SERVICES_ADMIN} ONLY (= games-services ∩ (admin|mod),
 *       materialized in Casdoor). A plain RUNNER cannot create. The SUPERADMIN creation
 *       gate (offered + enabled + quota) is enforced in {@link GameInstanceService}.</li>
 *   <li>{@code suspend}/{@code resume}/{@code terminate} — {@code GAMES_SERVICES_ADMIN} OR
 *       {@code GAMES_SERVICES_RUNNER} (mod-delegated run/stop).</li>
 * </ul>
 * Every row is scoped to the caller's own brand via {@link PrincipalDomain} (resolved from the
 * validated issuer); owner == {@code jwt.getSubject()} on create. Fail-closed.
 */
@RestController
@RequestMapping("/bff/games-services/instances")
@Validated
public class GameInstanceController {

    private static final Logger log = LoggerFactory.getLogger(GameInstanceController.class);

    private final GameInstanceService service;
    private final DomainRegistry domainRegistry;

    public GameInstanceController(GameInstanceService service, DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String subject(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return auth == null ? null : auth.getName();
    }

    // ── READ (any games-services member, own brand) ──────────────────────────────

    @PreAuthorize("hasRole('GAMES_SERVICES')")
    @Operation(summary = "List", operationId = "gameInstanceList")
    @GetMapping("")
    public Flux<GameInstanceResponse> list(Authentication auth) {
        return service.list(scope(auth)).map(GameInstanceResponse::of);
    }

    @PreAuthorize("hasRole('GAMES_SERVICES')")
    @Operation(summary = "Get", operationId = "gameInstanceGet")
    @GetMapping("/{id}")
    public Mono<GameInstanceResponse> get(
            @PathVariable @NotBlank @Size(max = 36) String id, Authentication auth) {
        return service.get(id, scope(auth)).map(GameInstanceResponse::of);
    }

    /** Connection info (protocol + NodePort + console path) for reaching the instance. Any
     *  games-services member may read their OWN brand's connection info. */
    @PreAuthorize("hasRole('GAMES_SERVICES')")
    @Operation(summary = "Connection", operationId = "gameInstanceConnection")
    @GetMapping("/{id}/connection")
    public Mono<GameInstanceConnectionResponse> connection(
            @PathVariable @NotBlank @Size(max = 36) String id, Authentication auth) {
        return service.connection(id, scope(auth))
                .map(t -> GameInstanceConnectionResponse.of(t.getT1(), t.getT2()));
    }

    // ── CREATE (admin-derived role ONLY; runner cannot create) ───────────────────

    @PreAuthorize("hasRole('GAMES_SERVICES_ADMIN')")
    @Operation(summary = "Create", operationId = "gameInstanceCreate")
    @PostMapping("")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<GameInstanceResponse> create(
            @Valid @RequestBody CreateGameInstanceRequest body, Authentication auth) {
        String subject = subject(auth);
        return service.create(body, subject, scope(auth))
                .doOnNext(i -> log.info("[games-instance] create slug={} name={} by={}",
                        i.slug(), i.name(), subject))
                .map(GameInstanceResponse::of);
    }

    // ── RUN/STOP (admin OR runner) ────────────────────────────────────────────────

    @PreAuthorize("hasAnyRole('GAMES_SERVICES_ADMIN', 'GAMES_SERVICES_RUNNER')")
    @Operation(summary = "Suspend", operationId = "gameInstanceSuspend")
    @PostMapping("/{id}/suspend")
    public Mono<GameInstanceResponse> suspend(
            @PathVariable @NotBlank @Size(max = 36) String id, Authentication auth) {
        return service.suspend(id, scope(auth)).map(GameInstanceResponse::of);
    }

    @PreAuthorize("hasAnyRole('GAMES_SERVICES_ADMIN', 'GAMES_SERVICES_RUNNER')")
    @Operation(summary = "Resume", operationId = "gameInstanceResume")
    @PostMapping("/{id}/resume")
    public Mono<GameInstanceResponse> resume(
            @PathVariable @NotBlank @Size(max = 36) String id, Authentication auth) {
        return service.resume(id, scope(auth)).map(GameInstanceResponse::of);
    }

    @PreAuthorize("hasAnyRole('GAMES_SERVICES_ADMIN', 'GAMES_SERVICES_RUNNER')")
    @Operation(summary = "Terminate", operationId = "gameInstanceTerminate")
    @PostMapping("/{id}/terminate")
    public Mono<GameInstanceResponse> terminate(
            @PathVariable @NotBlank @Size(max = 36) String id, Authentication auth) {
        return service.terminate(id, scope(auth)).map(GameInstanceResponse::of);
    }
}
