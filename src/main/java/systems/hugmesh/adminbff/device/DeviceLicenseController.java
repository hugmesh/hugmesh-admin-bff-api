package systems.hugmesh.adminbff.device;

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
import systems.hugmesh.adminbff.web.dto.GrantLicenseRequest;
import systems.hugmesh.adminbff.web.dto.RegisterDeviceRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The DEVICE-LICENSE REGISTRY admin surface — the SUPERADMIN console that governs which
 * operator may SSH into which mesh node, and the signed {@code /export} both enforcement
 * layers compile from. SECURITY-CRITICAL.
 *
 * <h3>Authorization (defence-in-depth)</h3>
 * The coarse gate on {@code /bff/admin/**} ({@code SecurityConfig.commonRoutes}) is
 * {@code hasAnyRole('ADMIN','SUPERADMIN')} — it lets the cross-domain infra super-role
 * AND a brand admin reach the path. From there:
 * <ul>
 *   <li>{@code GET ""} — {@code hasAnyRole('ADMIN','SUPERADMIN')}. The ADMIN
 *       READ-ONLY-OWN-DOMAIN wall is enforced DOWNSTREAM in the repo/service scope branch
 *       ({@link PrincipalDomain}): a scoped ADMIN literally cannot read another brand's rows
 *       even though it passes the coarse gate; SUPERADMIN (unscoped) reads all.</li>
 *   <li>Every MUTATION (register / de-register / grant / revoke) —
 *       {@code @PreAuthorize("hasRole('SUPERADMIN')")}: an ADMIN is 403 (it may VIEW but
 *       never MUTATE). MOD/USER never reach the coarse gate at all.</li>
 *   <li>{@code GET /export} — {@code @PreAuthorize("hasRole('SUPERADMIN')")} AND served
 *       only over the in-cluster mTLS transport ({@code server.ssl.client-auth=need} in
 *       the deployment); UNSCOPED + SIGNED per-mesh. (No ROLE_USER/ROLE_ADMIN principal
 *       reaches it; the per-node sync agent presents the SUPERADMIN service identity over
 *       mTLS.)</li>
 * </ul>
 * This controller NEVER evaluates SSH authorization at connect time — it only edits rows
 * and emits the compiled, signed export the two layers consume.
 */
@RestController
@RequestMapping("/bff/admin/device-licenses")
@Validated
public class DeviceLicenseController {

    private static final Logger log = LoggerFactory.getLogger(DeviceLicenseController.class);

    private final DeviceRegistryService devices;
    private final SshLicenseService licenses;
    private final DeviceRegistryExportService export;
    private final DomainRegistry domainRegistry;
    private final DevicePendingService pending;

    public DeviceLicenseController(DeviceRegistryService devices, SshLicenseService licenses,
                                   DeviceRegistryExportService export, DomainRegistry domainRegistry,
                                   DevicePendingService pending) {
        this.devices = devices;
        this.licenses = licenses;
        this.export = export;
        this.domainRegistry = domainRegistry;
        this.pending = pending;
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String actor(Authentication auth) {
        return auth == null ? "superadmin" : auth.getName();
    }

    // ── List (ADMIN own-domain RO via scope; SUPERADMIN all) ────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "List", operationId = "deviceLicenseList")
    @GetMapping("")
    public Mono<Map<String, Object>> list(Authentication auth) {
        PrincipalDomain scope = scope(auth);
        return Mono.zip(
                devices.list(scope).collectList(),
                licenses.list(scope).collectList(),
                (devs, lics) -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("devices", devs);
                    out.put("licenses", lics);
                    return out;
                });
    }

    // ── PENDING pick-list (headscale enrolled LEFT-JOIN registry; READ-ONLY) ─────
    /**
     * The PENDING pick-list for the machine_key_fp AUTO-CAPTURE flow — every
     * headscale-enrolled node LEFT-JOINed with {@code device_registry}, so a SUPERADMIN can
     * pick an unregistered fingerprint and assign its owner_type/domain/image_type. The
     * fingerprint is an OPAQUE token (captured from headscale, never typed). READ-ONLY —
     * coarse gate {@code hasAnyRole('ADMIN','SUPERADMIN')}; the per-row wall is the same
     * {@link PrincipalDomain} branch as the device list (ADMIN sees own-domain REGISTERED rows
     * only; the unregistered candidates are SUPERADMIN-only, in {@link DevicePendingService}).
     *
     * <p>⚠ ADVISORY / ships dark: with {@code app.registry.headscale.enabled=false} (default)
     * this degrades to the registry-only view (no enrolled-but-unassigned candidates) — the
     * auto-capture flow has nothing to offer until a live control node is wired + the flag set.
     */
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    @Operation(summary = "Pending", operationId = "deviceLicensePending")
    @GetMapping("/pending")
    public Mono<Map<String, Object>> pending(Authentication auth) {
        return pending.pending(scope(auth)).collectList().map(nodes -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("nodes", nodes);
            return out;
        });
    }

    // ── Register a device (SUPERADMIN; FIX-NODEFAULT guard + headscale re-validate) ──
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Register", operationId = "deviceLicenseRegister")
    @PostMapping("/register")
    public Mono<ResponseEntity<Device>> register(@Valid @RequestBody RegisterDeviceRequest b, Authentication auth) {
        Device draft = new Device(null, b.machineKeyFp(), b.hostname(), b.tailnetId(),
                b.imageType(), b.hardwareClass(), b.ownerType(), b.physicalOwner(),
                b.domain(), b.meshId(), null, null);
        return devices.register(draft)
                .doOnNext(d -> log.info("[device-licenses] register by {} -> id={}", actor(auth), d.id()))
                .map(ResponseEntity::ok)
                // FIX-NODEFAULT: the multi-issuer / non-'default' residency guard surfaces
                // as a clean 422 {error}, never a silent default.
                .onErrorResume(IllegalArgumentException.class,
                        e -> Mono.error(ApiException.unprocessable(e.getMessage())));
    }

    // ── De-register a device (SUPERADMIN) ───────────────────────────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Deregister", operationId = "deviceLicenseDeregister")
    @DeleteMapping("/{deviceId}")
    public Mono<ResponseEntity<Map<String, Object>>> deregister(
            @PathVariable @NotBlank @Size(max = 36) String deviceId,
            Authentication auth) {
        return devices.deregister(deviceId, scope(auth))
                .map(n -> ResponseEntity.ok(Map.of("deregistered", n)));
    }

    // ── Grant a DEVICE-scoped license (SUPERADMIN; FIX-PINKEY) ──────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Grant device", operationId = "deviceLicenseGrantDevice")
    @PostMapping("/{deviceId}/grant")
    public Mono<ResponseEntity<SshLicense>> grantDevice(
            @PathVariable @NotBlank @Size(max = 36) String deviceId,
            @Valid @RequestBody GrantLicenseRequest b, Authentication auth) {
        return licenses.grantDevice(b.operator(), deviceId, b.keyFingerprints(), actor(auth))
                .map(ResponseEntity::ok)
                .onErrorResume(IllegalArgumentException.class,
                        e -> Mono.error(ApiException.unprocessable(e.getMessage())));
    }

    // ── Grant a DOMAIN-scoped license (SUPERADMIN; FIX-PINKEY) ──────────────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Grant domain", operationId = "deviceLicenseGrantDomain")
    @PostMapping("/domains/{domain}/grant")
    public Mono<ResponseEntity<SshLicense>> grantDomain(
            @PathVariable @NotBlank @Size(max = 64) String domain,
            @Valid @RequestBody GrantLicenseRequest b, Authentication auth) {
        return licenses.grantDomain(b.operator(), domain, b.keyFingerprints(), actor(auth))
                .map(ResponseEntity::ok)
                // (d) FIX-NODEFAULT: a 'default'/blank/unknown target-domain guard surfaces
                // as a clean 422 {error}, never a silently-useless DOMAIN license.
                .onErrorResume(IllegalArgumentException.class,
                        e -> Mono.error(ApiException.unprocessable(e.getMessage())));
    }

    // ── Revoke a license (SUPERADMIN; CAS audit + gen bump, FIX-REVOKE) ──────────
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Revoke", operationId = "deviceLicenseRevoke")
    @DeleteMapping("/licenses/{licenseId}")
    public Mono<ResponseEntity<Map<String, Object>>> revoke(
            @PathVariable @NotBlank @Size(max = 36) String licenseId,
            Authentication auth) {
        return licenses.revoke(licenseId, actor(auth), scope(auth))
                .map(n -> ResponseEntity.ok(Map.of("revoked", n)));
    }

    // ── Signed export (SUPERADMIN | internal mTLS) — per-mesh OR per-node ────────
    /**
     * The signed device-registry export, in one of two SHAPES selected by the query param:
     * <ul>
     *   <li>{@code ?node=<machine_key_fp>} — PER-NODE (Layer-B). The signed body carries
     *       ONLY the authorized-operators for THAT ONE node, so an admin-owned node caching
     *       it learns NOTHING about any other node's / any other domain's operators or key
     *       fingerprints [CONFIDENTIALITY HARDENING]. An unknown fp yields an EMPTY signed
     *       body (fail-closed, never a leaky error). Takes precedence when BOTH are given.</li>
     *   <li>{@code ?mesh=<id>} — PER-MESH (Layer-A, UNCHANGED). The signed body carries
     *       EVERY node in the mesh — the control node's headscale policy generator needs the
     *       whole mesh.</li>
     * </ul>
     * Same SUPERADMIN | internal-mTLS gate, canonical-bytes format, detached Ed25519
     * signature and monotonic generation for both shapes — only the {@code operators[]} body
     * is narrowed for the per-node shape. Exactly one of {@code node}/{@code mesh} is
     * required (a request supplying neither is a clean 400).
     */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Export", operationId = "deviceLicenseExport")
    @GetMapping("/export")
    public Mono<ExportModels.SignedExport> export(
            @RequestParam(value = "mesh", required = false) @Size(max = 64) String mesh,
            @RequestParam(value = "node", required = false) @Size(max = 128) String node) {
        if (node != null && !node.isBlank()) {
            return export.exportNode(node);
        }
        if (mesh != null && !mesh.isBlank()) {
            return export.exportMesh(mesh);
        }
        return Mono.error(ApiException.badRequest(
                "exactly one of 'node' (per-node, Layer-B) or 'mesh' (per-mesh, Layer-A) is required"));
    }
}
