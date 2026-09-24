package net.hugmesh.adminbff.tor;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.tor.TorExportModels.SignedTorExport;
import net.hugmesh.adminbff.web.dto.TorUpstreamRequest;

/**
 * The node Tor admin surface, {@code /bff/admin/tor} (hugmesh-admin-bff-api#108).
 *
 * <h3>Authorization</h3>
 * The coarse gate on {@code /bff/admin/**} is {@code hasAnyRole('ADMIN','SUPERADMIN')}. Then:
 * <ul>
 *   <li>{@code GET /nodes} — ADMIN or SUPERADMIN. A SUPERADMIN sees every node's onions,
 *       registry join and upstream; a domain ADMIN sees only their own domain's onion
 *       (and the primary only for {@code default}), with node identity and routing
 *       redacted ({@link TorNodeService#redactFor}).</li>
 *   <li>{@code PUT /nodes/{fp}/upstream} — SUPERADMIN only.</li>
 *   <li>{@code GET /export?node=} — SUPERADMIN only, and served to the node agent over the
 *       in-cluster mTLS transport like every other signed per-node export
 *       (device-licenses, egress-vpn, device-storage-pools).</li>
 * </ul>
 * The per-domain list has no endpoint here: it is the {@code tor-onion} key of
 * {@code /bff/admin/domain-capabilities} (SUPERADMIN grants, the domain ADMIN opts in, the
 * {@code ' global'} row is the platform-wide switch).
 */
@RestController
@RequestMapping("/bff/admin/tor")
@Validated
public class TorAdminController {

    private final TorNodeService nodes;
    private final TorExportService export;
    private final DomainRegistry domainRegistry;

    public TorAdminController(TorNodeService nodes, TorExportService export, DomainRegistry domainRegistry) {
        this.nodes = nodes;
        this.export = export;
        this.domainRegistry = domainRegistry;
    }

    private static String actor(Authentication auth) {
        return auth == null ? "superadmin" : auth.getName();
    }

    /** Each node's exported onions as {@code {primary, domains: {slug: onion}}}. */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "List node onions", operationId = "torListNodes")
    @GetMapping("/nodes")
    public Flux<TorNodeView> listNodes(Authentication auth) {
        return nodes.list(PrincipalDomain.of(auth, domainRegistry));
    }

    /** Manage one node's {@code /etc/hugmesh/tor/upstream} (null = the agent's default). */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Set node upstream", operationId = "torSetNodeUpstream")
    @PutMapping("/nodes/{nodeFp}/upstream")
    public Mono<TorNodeConfig> setUpstream(
            @PathVariable @NotBlank @Size(max = 128) String nodeFp,
            @Valid @RequestBody TorUpstreamRequest body, Authentication auth) {
        return nodes.setUpstream(nodeFp, body.upstream(), actor(auth));
    }

    /**
     * The signed per-node Tor export the node agent verifies and writes into
     * {@code /etc/hugmesh/tor/upstream} and {@code /etc/hugmesh/tor/domains}. An unknown
     * fingerprint gets an empty signed body with nothing managed.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Export", operationId = "torExport")
    @GetMapping("/export")
    public Mono<SignedTorExport> export(
            @RequestParam(value = "node") @NotBlank @Size(max = 128) String node) {
        return export.exportNode(node);
    }
}
