package net.hugmesh.adminbff.device;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

/**
 * Write/read surface for {@code device_registry} — the identity + physical ownership +
 * DOMAIN RESIDENCY of each mesh node. SUPERADMIN mutates (register / de-register);
 * ADMIN reads own-domain only (the scope branch in
 * {@link DeviceRegistryRepository#list(PrincipalDomain)}).
 *
 * <h3>FIX-NODEFAULT (register guard)</h3>
 * Residency is the load-bearing factor of the ADMIN cross-domain-deny wall, so register
 * REFUSES to stamp a meaningless residency:
 * <ul>
 *   <li>It REFUSES when the platform is NOT multi-issuer
 *       ({@code !DomainRegistry.isMultiIssuer()}) UNLESS
 *       {@code app.registry.allow-single-issuer=true} (a documented footgun override) —
 *       because a single-issuer cluster emits {@code DOMAIN_default} for everyone, so a
 *       per-domain SSH boundary cannot actually be drawn.</li>
 *   <li>It REJECTS {@code domain == 'default'} outright — if every node were resident in
 *       {@code default} the clause-2 wall ("DENY if device.domain != DOMAIN_P") would be
 *       vacuous (every node would read as the caller's brand).</li>
 * </ul>
 * Either violation is a hard {@link IllegalArgumentException} (the controller maps it to
 * a 422), never a silent default.
 */
@Service
public class DeviceRegistryService {

    private static final Logger log = LoggerFactory.getLogger(DeviceRegistryService.class);

    private final DeviceRegistryRepository repo;
    private final DomainRegistry domainRegistry;
    private final boolean allowSingleIssuer;
    private final HeadscaleNodesClient headscale;
    private final RegistryHeadscaleProperties headscaleProps;

    @org.springframework.beans.factory.annotation.Autowired
    public DeviceRegistryService(DeviceRegistryRepository repo, DomainRegistry domainRegistry,
                                 @Value("${app.registry.allow-single-issuer:false}") boolean allowSingleIssuer,
                                 HeadscaleNodesClient headscale,
                                 RegistryHeadscaleProperties headscaleProps) {
        this.repo = repo;
        this.domainRegistry = domainRegistry;
        this.allowSingleIssuer = allowSingleIssuer;
        this.headscale = headscale;
        this.headscaleProps = headscaleProps;
    }

    /**
     * Convenience constructor for callers (tests) that don't exercise the HEADSCALE-ANCHORED
     * register re-validation: defaults the headscale collaborators to a DISABLED instance
     * (enabled=false), so {@link #register(Device)} behaves exactly as before (no re-query,
     * accept the supplied fp). Production always uses the {@code @Autowired} 5-arg constructor
     * with the real {@link HeadscaleNodesClient} + bound {@link RegistryHeadscaleProperties}.
     */
    public DeviceRegistryService(DeviceRegistryRepository repo, DomainRegistry domainRegistry,
                                 boolean allowSingleIssuer) {
        this(repo, domainRegistry, allowSingleIssuer,
                new HeadscaleNodesClient(new RegistryHeadscaleProperties(),
                        new com.fasterxml.jackson.databind.ObjectMapper()),
                new RegistryHeadscaleProperties());
    }

    /**
     * Register a device. Enforces the FIX-NODEFAULT guard, then INSERTs (idempotent on the
     * stable {@code machine_key_fp}: an already-registered fingerprint returns the existing
     * row unchanged rather than violating the UNIQUE constraint).
     *
     * @return the registered device (existing or newly created)
     */
    public Mono<Device> register(Device d) {
        // Guard then headscale-revalidate then idempotent insert.
        return Mono.defer(() -> performRegister(d));
    }

    /** Run the FIX-NODEFAULT guard, headscale re-validation, and idempotent DB insert. */
    private Mono<Device> performRegister(Device d) {
        try {
            guard(d);
        } catch (IllegalArgumentException e) {
            return Mono.error(e);
        }
        // HEADSCALE-ANCHORED re-validation [machine_key_fp AUTO-CAPTURE]: confirm the fp is
        // still enrolled in headscale AND its meshId matches before inserting.
        return revalidateAgainstHeadscale(d.machineKeyFp(), d.meshId())
                .then(repo.findByMachineKey(d.machineKeyFp())
                        .doOnNext(existing -> log.info(
                                "[device-registry] {} already registered (id={}, domain={}) — no-op",
                                d.machineKeyFp(), existing.id(), existing.domain()))
                        .switchIfEmpty(Mono.defer(() -> repo.insert(d)
                                .doOnNext(saved -> log.info(
                                        "[device-registry] registered {} host={} owner_type={} domain={} mesh={} (id={})",
                                        saved.machineKeyFp(), saved.hostname(), saved.ownerType(),
                                        saved.domain(), saved.meshId(), saved.id())))));
    }

    /**
     * RE-VALIDATE the opaque fingerprint against the live headscale node set at register time
     * [machine_key_fp AUTO-CAPTURE, headscale-anchored hybrid]. Headscale minted the machine
     * keys, so it is the authority for "is this fp still enrolled, and in this mesh?". On a
     * mismatch (fp not enrolled, or enrolled under a DIFFERENT mesh) the register FAILS CLOSED
     * with a {@link ApiException#conflict(String) 409} — copying a stale/foreign fp into the
     * registry would silently deny that real node forever.
     *
     * <h3>⚠ BREAK-GLASS (ships dark)</h3>
     * When {@code app.registry.headscale.allow-manual-fp=true} (the DEFAULT, because the
     * canonical fp field — machineKey vs nodeKey — is UNCONFIRMED without a live control node;
     * see {@code docs/CANONICAL-FP.md}) the re-validation is ADVISORY: a failed/absent match is
     * logged LOUDLY and the manual/opaque fingerprint is accepted anyway. Likewise when the
     * feature is disabled ({@code enabled=false}) there is nothing to re-query, so accept.
     * Flip {@code allow-manual-fp=false} ONLY after freezing the canonical field on a live node
     * to make this gate load-bearing. Returns an empty {@link Mono} on accept; errors on a
     * fail-closed reject.
     */
    Mono<Void> revalidateAgainstHeadscale(String offeredFp, String meshId) {
        if (!headscaleProps.isEnabled()) {
            log.debug("[device-registry] headscale re-validate SKIPPED (app.registry.headscale.enabled=false) "
                    + "— fp {} accepted as supplied (ships-dark)", offeredFp);
            return Mono.empty();
        }
        // Use a non-empty matched marker so an ACCEPTED match (which produces an empty Mono<Void>)
        // is NOT confused with NO-match by the trailing switchIfEmpty. We map the matched node to
        // a present element, then resolve the accept/reject there; the switchIfEmpty fires ONLY
        // when the filter found nothing (truly not enrolled).
        return headscale.listNodes()
                .filter(n -> offeredFp.equals(n.machineKeyFp()))
                .next()
                // Enrolled: verify the mesh id matches (advisory unless enforcing).
                .flatMap(match -> checkMeshMatch(match, offeredFp, meshId))
                .switchIfEmpty(Mono.defer(() -> failClosedOrBreakGlass(offeredFp,
                        "offered fingerprint is NOT currently enrolled in headscale")
                        .thenReturn(Boolean.TRUE)))
                .then();
    }

    /** Accept when the enrolled node's mesh id matches; otherwise fail-closed or break-glass. */
    private Mono<Boolean> checkMeshMatch(HeadscaleNode match, String offeredFp, String meshId) {
        if (meshMatches(match.meshId(), meshId)) {
            log.info("[device-registry] headscale re-validate OK: fp {} still enrolled, mesh matches", offeredFp);
            return Mono.just(Boolean.TRUE);
        }
        return failClosedOrBreakGlass(offeredFp,
                "offered fingerprint is enrolled in headscale but its mesh ('" + match.meshId()
                + "') does not match the requested meshId ('" + meshId + "')")
                .thenReturn(Boolean.TRUE);
    }

    /** A blank reported mesh is advisory-undeterminable → treat as a match (we cannot disprove
     *  it); otherwise require either side to contain the other (headscale reports a tag like
     *  {@code tag:mesh_<id>} while the registry stores the bare id). */
    private static boolean meshMatches(String reportedMesh, String requestedMesh) {
        if (reportedMesh == null || reportedMesh.isBlank()) return true;
        if (requestedMesh == null || requestedMesh.isBlank()) return true;
        return reportedMesh.equals(requestedMesh)
                || reportedMesh.contains(requestedMesh)
                || requestedMesh.contains(reportedMesh);
    }

    private Mono<Void> failClosedOrBreakGlass(String offeredFp, String why) {
        if (headscaleProps.isAllowManualFp()) {
            log.warn("[device-registry] HEADSCALE RE-VALIDATE FAILED for fp {} ({}). "
                    + "BREAK-GLASS allow-manual-fp=true (ships-dark) — accepting the manual fingerprint anyway. "
                    + "Confirm the canonical fp field on a live control node + freeze docs/CANONICAL-FP.md, "
                    + "then set app.registry.headscale.allow-manual-fp=false to make this fail-closed.", offeredFp, why);
            return Mono.empty();
        }
        log.warn("[device-registry] HEADSCALE RE-VALIDATE FAILED for fp {} ({}) — 409 fail-closed "
                + "(allow-manual-fp=false)", offeredFp, why);
        return Mono.error(net.hugmesh.commons.web.ApiException.conflict(
                "device registration rejected: " + why
                + " (headscale re-validation, fail-closed). To override temporarily set "
                + "app.registry.headscale.allow-manual-fp=true."));
    }

    /** The FIX-NODEFAULT register guard — see the class javadoc. Throws on violation. */
    void guard(Device d) {
        if (!domainRegistry.isMultiIssuer() && !allowSingleIssuer) {
            throw new IllegalArgumentException(
                    "device registration requires a multi-issuer (per-brand) registry so a "
                    + "per-domain SSH boundary can be drawn; set app.registry.allow-single-issuer=true "
                    + "to override (single-issuer footgun)");
        }
        String domain = d.domain();
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("device residency domain is required (no default)");
        }
        if (DomainRegistry.DEFAULT_DOMAIN.equals(domain)) {
            throw new IllegalArgumentException(
                    "device residency domain must NOT be 'default' [FIX-NODEFAULT]: a 'default' "
                    + "residency would make the ADMIN cross-domain-deny wall vacuous");
        }
    }

    /** Devices VISIBLE to the given tenant scope — the ADMIN read surface (own-domain
     *  only; SUPERADMIN sees all). */
    public Flux<Device> list(PrincipalDomain scope) {
        return repo.list(scope);
    }

    /** A single device by id (UNSCOPED — used by the grant flow to resolve a device's
     *  residency + owner_type). */
    public Mono<Device> findById(String id) {
        return repo.findById(id);
    }

    /** De-register a device by id within the given scope. SUPERADMIN-gated at the
     *  controller; returns the rows-deleted count (0 = absent / out of scope). */
    public Mono<Long> deregister(String id, PrincipalDomain scope) {
        return repo.delete(id, scope)
                .doOnNext(n -> log.info("[device-registry] de-register id={} rows={}", id, n));
    }
}
