package net.hugmesh.adminbff.directory;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.List;

/**
 * Service-to-service read for user-bff's member directory ({@code GET /bff/user/directory/search}).
 * Guarded like every {@code /bff/internal/**} route by the shared internal token, so only
 * user-bff can call it; user-bff passes the scope it resolved from the caller's VALIDATED JWT
 * ({@code domain}, and {@code superadmin} only for a SUPERADMIN), so the browser never names a domain.
 */
@RestController
@RequestMapping("/bff/internal/directory")
@Validated
public class MeshUserDirectoryInternalController {

    private final MeshUserDirectoryService service;

    public MeshUserDirectoryInternalController(MeshUserDirectoryService service) {
        this.service = service;
    }

    @Operation(summary = "Search mesh users", operationId = "meshUserDirectoryInternalSearch")
    @GetMapping("/search")
    public Mono<List<MeshUser>> search(
            @RequestParam(name = "q", required = false, defaultValue = "") @Size(max = 200) String q,
            @RequestParam(name = "limit", required = false, defaultValue = "10")
            @Min(1) @Max(MeshUserDirectoryService.MAX_LIMIT) int limit,
            @RequestParam(name = "domain", required = false, defaultValue = "") @Size(max = 255) String domain,
            @RequestParam(name = "superadmin", required = false, defaultValue = "false") boolean superadmin) {
        PrincipalDomain scope = superadmin ? PrincipalDomain.superadminFor(domain) : PrincipalDomain.forDomain(domain);
        return service.search(scope, q, limit);
    }
}
