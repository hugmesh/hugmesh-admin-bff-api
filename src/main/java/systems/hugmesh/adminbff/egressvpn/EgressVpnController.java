package systems.hugmesh.adminbff.egressvpn;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.adminbff.web.dto.AssignVpnRequest;
import systems.hugmesh.adminbff.web.dto.ImportVpnConfigRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The EGRESS-VPN admin surface — the SUPERADMIN console that imports provider VPN configs
 * and assigns them to nodes/domains so PUBLIC-facing pods egress via the VPN. CLONES the
 * {@link systems.hugmesh.adminbff.device.DeviceLicenseController} authorization model.
 *
 * <h3>Authorization (defence-in-depth)</h3>
 * The coarse gate on {@code /bff/admin/**} ({@code SecurityConfig.commonRoutes}) is
 * {@code hasAnyRole('ADMIN','SUPERADMIN')}. From there:
 * <ul>
 *   <li>{@code GET ""} — {@code hasAnyRole('ADMIN','SUPERADMIN')}. The ADMIN
 *       READ-ONLY-OWN-DOMAIN wall is enforced DOWNSTREAM in the repo/service scope branch
 *       ({@link PrincipalDomain}): a scoped ADMIN cannot read another brand's configs/
 *       assignments even though it passes the coarse gate; SUPERADMIN (unscoped) reads
 *       all.</li>
 *   <li>Every MUTATION (import / revoke config / assign / unassign) —
 *       {@code @PreAuthorize("hasRole('SUPERADMIN')")}: an ADMIN is 403. MOD/USER never
 *       reach the coarse gate.</li>
 * </ul>
 *
 * <p>Secrets stay off-DB: an imported config's bytes (and the private VPN key) live in a
 * K8s Secret (ESO); this controller validates the upload (a malformed config is a 422) and
 * stores only the {@code secret_ref} + parsed metadata.
 */
@RestController
@RequestMapping("/bff/admin/egress-vpn")
@Validated
public class EgressVpnController {

    private static final Logger log = LoggerFactory.getLogger(EgressVpnController.class);

    private final EgressVpnService vpn;
    private final VpnExportService export;
    private final DomainRegistry domainRegistry;

    public EgressVpnController(EgressVpnService vpn, VpnExportService export, DomainRegistry domainRegistry) {
        this.vpn = vpn;
        this.export = export;
        this.domainRegistry = domainRegistry;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String actor(Authentication auth) {
        return auth == null ? "superadmin" : auth.getName();
    }

    // ── List (ADMIN own-domain RO via scope; SUPERADMIN all) ────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "List", operationId = "egressVpnList")
    @GetMapping("")
    public Mono<Map<String, Object>> list(Authentication auth) {
        PrincipalDomain scope = scope(auth);
        return Mono.zip(
                vpn.listConfigs(scope).collectList(),
                vpn.listAssignments(scope).collectList(),
                (cfgs, asgs) -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("configs", cfgs);
                    out.put("assignments", asgs);
                    return out;
                });
    }

    // ── Import a config (SUPERADMIN; parse-validate -> 422 on bad) ───────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Import config", operationId = "egressVpnImportConfig")
    @PostMapping("/configs")
    public Mono<ResponseEntity<VpnConfig>> importConfig(@Valid @RequestBody ImportVpnConfigRequest b,
                                                        Authentication auth) {
        // Default the secret_ref to a stable per-(domain,name) name when none supplied —
        // the actual bytes live in that K8s Secret (ESO); never in the DB.
        String secretRef = (b.secretRef() == null || b.secretRef().isBlank())
                ? "egress-vpn-" + b.domain() + "-" + b.name()
                : b.secretRef();
        return vpn.importConfig(b.domain(), b.name(), b.provider(), b.config(), secretRef, actor(auth))
                .doOnNext(c -> log.info("[egress-vpn] import by {} -> id={} kind={}", actor(auth), c.id(), c.kind()))
                .map(ResponseEntity::ok)
                // FIX-NODEFAULT + parse failure surface as a clean 422 {error}.
                .onErrorResume(IllegalArgumentException.class,
                        e -> Mono.error(ApiException.unprocessable(e.getMessage())));
    }

    // ── Revoke a config (SUPERADMIN; CAS audit + cascade-revoke assignments) ─────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Revoke config", operationId = "egressVpnRevokeConfig")
    @DeleteMapping("/configs/{configId}")
    public Mono<ResponseEntity<Map<String, Object>>> revokeConfig(
            @PathVariable @NotBlank @Size(max = 36) String configId,
            Authentication auth) {
        return vpn.revokeConfig(configId, actor(auth), scope(auth))
                .map(n -> ResponseEntity.ok(Map.of("revoked", n)));
    }

    // ── Assign a config to a NODE (SUPERADMIN) ──────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Assign node", operationId = "egressVpnAssignNode")
    @PostMapping("/configs/{configId}/assign/node/{nodeFp}")
    public Mono<ResponseEntity<VpnNodeAssignment>> assignNode(
            @PathVariable @NotBlank @Size(max = 36) String configId,
            @PathVariable @NotBlank @Size(max = 128) String nodeFp,
            @Valid @RequestBody(required = false) AssignVpnRequest b, Authentication auth) {
        String svc = b == null ? null : b.serviceSlug();
        return vpn.assignNode(configId, nodeFp, svc, actor(auth))
                .map(ResponseEntity::ok)
                .onErrorResume(IllegalArgumentException.class,
                        e -> Mono.error(ApiException.unprocessable(e.getMessage())));
    }

    // ── Assign a config to a DOMAIN (SUPERADMIN) ────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Assign domain", operationId = "egressVpnAssignDomain")
    @PostMapping("/configs/{configId}/assign/domain/{domain}")
    public Mono<ResponseEntity<VpnNodeAssignment>> assignDomain(
            @PathVariable @NotBlank @Size(max = 36) String configId,
            @PathVariable @NotBlank @Size(max = 64) String domain,
            @Valid @RequestBody(required = false) AssignVpnRequest b, Authentication auth) {
        String svc = b == null ? null : b.serviceSlug();
        return vpn.assignDomain(configId, domain, svc, actor(auth))
                .map(ResponseEntity::ok)
                .onErrorResume(IllegalArgumentException.class,
                        e -> Mono.error(ApiException.unprocessable(e.getMessage())));
    }

    // ── Un-assign (revoke an assignment) (SUPERADMIN; CAS audit) ────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Revoke assignment", operationId = "egressVpnRevokeAssignment")
    @DeleteMapping("/assignments/{assignmentId}")
    public Mono<ResponseEntity<Map<String, Object>>> revokeAssignment(
            @PathVariable @NotBlank @Size(max = 36) String assignmentId,
            Authentication auth) {
        return vpn.revokeAssignment(assignmentId, actor(auth), scope(auth))
                .map(n -> ResponseEntity.ok(Map.of("revoked", n)));
    }

    // ── Signed PER-NODE export (SUPERADMIN | internal mTLS) ─────────────────────
    /**
     * The signed per-node egress-VPN export the node-level reconcile agent consumes
     * (CLONES the device-license-registry {@code /export?node=}). The signed body carries
     * the ACTIVE configs assigned onto THAT ONE node (via a DEVICE assignment or a DOMAIN
     * assignment matching the node's residency) — the {@code secret_ref} (so the agent
     * fetches the {@code .conf} from its K8s Secret), NEVER the private key. Canonical
     * line-oriented bytes + detached Ed25519 + monotonic generation; the agent verifies
     * against the BAKED key-USB public half and fail-closes (keeps last-good) on an
     * unsigned/tampered/rolled-back payload. An UNKNOWN fp yields an EMPTY signed body
     * (fail-closed, never a leaky error). SUPERADMIN-gated AND served only over the
     * in-cluster mTLS transport in the deployment.
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Export", operationId = "egressVpnExport")
    @GetMapping("/export")
    public Mono<VpnExportModels.SignedVpnExport> export(
            @RequestParam(value = "node") @NotBlank @Size(max = 128) String node) {
        return export.exportNode(node);
    }
}
