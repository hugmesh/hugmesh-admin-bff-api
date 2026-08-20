package net.hugmesh.adminbff.egressvpn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Write/read surface for the egress-VPN control plane ({@code vpn_config} +
 * {@code vpn_node_assignment}). SUPERADMIN imports/revokes configs and assigns/unassigns;
 * ADMIN reads own-domain only (the scope branch in the repos). CLONES
 * {@link net.hugmesh.adminbff.device.SshLicenseService}: an idempotent
 * findActive-then-insert + a CAS revoke that NEVER deletes (the row is the audit trail) at
 * a monotonic generation.
 *
 * <h3>FIX-NODEFAULT</h3>
 * A config's residency {@code domain} (and an assignment's home domain, stamped from the
 * config) MUST be a real, known, non-'default' brand — the ADMIN cross-domain-deny wall is
 * vacuous otherwise. A violation is a hard {@link IllegalArgumentException} the controller
 * maps to a 422, never a silent default.
 *
 * <h3>Secrets off-DB</h3>
 * A config row holds ONLY a {@code secret_ref} + the parsed non-secret metadata. The
 * {@code .conf}/{@code .ovpn} bytes (and the private VPN key) ride a K8s Secret / the
 * key-USB — the parser validates the body but never persists it to the DATABASE. On a FRESH
 * import the validated bytes are handed to the {@link VpnConfigSecretWriter} seam (the
 * default-off runtime delivery leg; the dark Noop drops them). The idempotent re-import
 * no-op deliberately does NOT re-deliver: the existing row's metadata was parsed from the
 * ORIGINAL bytes, and overwriting the Secret with a different body under the same
 * (domain, name) would silently diverge row metadata from Secret content.
 *
 * <h3>DEVICE assignment guards</h3>
 * A DEVICE assignment resolves the target node by its {@code machine_key_fp} FIRST and
 * REJECTS (a) an unknown node, (b) a node resident in a DIFFERENT brand than the config
 * (cross-tenant assignment), and (c) a SUPERADMIN-owned node (core nodes are not
 * domain-public-egress targets). The assignment's home {@code domain} is stamped from the
 * CONFIG's residency, never the caller.
 *
 * <h3>Pod-labeling fast path</h3>
 * Every assignment activate/deactivate (fresh assign, un-assign, and the revoke-config
 * cascade) triggers ONE {@link VpnEgressLabeler#reconcile()} AFTER the row commit — the same
 * convergence the {@link VpnEgressLabelReconciler} drift sweep runs on a cadence, so the
 * opt-in {@code hugmesh.net/vpn-egress} label lands/vanishes promptly on a mutation and
 * the two paths cannot diverge. {@code reconcile()} never errors (the dark Noop returns 0; the
 * real labeler swallows cluster failures), so the admin mutation never fails on it.
 *
 * <h3>Node report-back</h3>
 * {@link #reportNodeState} closes the propagation loop the node-level
 * {@code hugmesh-vpn-reconcile} agent drives: the agent PUTs its per-node applied/failed/
 * degraded outcome and the rows that FED that node's signed export (the SAME compile
 * predicate: ACTIVE DEVICE assignments on the fp + ACTIVE DOMAIN assignments on the node's
 * residency, plus their still-active configs) transition out of {@code pending}. Fail-closed:
 * an unknown fp or a SUPERADMIN-owned node transitions NOTHING (0 rows, never a leaky error).
 */
@Service
public class EgressVpnService {

    private static final Logger log = LoggerFactory.getLogger(EgressVpnService.class);

    private final VpnConfigRepository configs;
    private final VpnNodeAssignmentRepository assignments;
    private final DeviceRegistryRepository devices;
    private final DomainRegistry domainRegistry;
    private final VpnConfigSecretWriter secretWriter;
    private final VpnEgressLabeler labeler;

    public EgressVpnService(VpnConfigRepository configs, VpnNodeAssignmentRepository assignments,
                            DeviceRegistryRepository devices, DomainRegistry domainRegistry,
                            VpnConfigSecretWriter secretWriter, VpnEgressLabeler labeler) {
        this.configs = configs;
        this.assignments = assignments;
        this.devices = devices;
        this.domainRegistry = domainRegistry;
        this.secretWriter = secretWriter;
        this.labeler = labeler;
    }

    // ── configs ─────────────────────────────────────────────────────────────────

    /**
     * Import a provider VPN config into {@code domain} under {@code name}. Parses +
     * VALIDATES the raw body (a malformed config is a 422; the kind + display endpoint are
     * extracted, the body itself is NEVER persisted — only the {@code secretRef} +
     * metadata are stored). Idempotent on an active (domain, name) — re-importing returns
     * the existing row unchanged. FIX-NODEFAULT: the domain must be a real, non-'default'
     * brand.
     */
    public Mono<VpnConfig> importConfig(String domain, String name, String provider,
                                        String configBody, String secretRef, String createdBy) {
        // Defer so all validation errors are surfaced as reactive errors.
        return Mono.defer(() -> performImportConfig(domain, name, provider, configBody, secretRef, createdBy));
    }

    /** Revoke a config by id (CAS audit + gen bump) AND cascade-revoke every active
     *  assignment referencing it (a config with no bytes can no longer back an egress).
     *  Returns the rows-updated count for the config (1 = revoked, 0 = absent/out of scope). */
    public Mono<Long> revokeConfig(String configId, String revokedBy, PrincipalDomain scope) {
        return configs.maxGeneration().flatMap(maxGen ->
                configs.revoke(configId, revokedBy, maxGen + 1, scope)
                        .flatMap(n -> {
                            if (n == 0L) return Mono.just(0L);
                            return assignments.maxGeneration()
                                    .flatMap(amax -> assignments.revokeByConfig(configId, revokedBy, amax + 1))
                                    .doOnNext(an -> log.info(
                                            "[egress-vpn] revoke config id={} by={} -> cascade-revoked {} assignment(s)",
                                            configId, revokedBy, an))
                                    // The cascade deactivated assignments — un-label promptly.
                                    .flatMap(an -> labeler.reconcile().thenReturn(n));
                        }));
    }

    public Flux<VpnConfig> listConfigs(PrincipalDomain scope) {
        return configs.list(scope);
    }

    // ── assignments ───────────────────────────────────────────────────────────────

    /**
     * Assign a config to ONE node (by its {@code machine_key_fp}), optionally narrowed to
     * one {@code serviceSlug}. Resolves the config + node FIRST and rejects: unknown
     * config/node, a node resident in a DIFFERENT brand than the config (cross-tenant), or
     * a SUPERADMIN-owned node. Idempotent on an active (node, service). The home domain is
     * the config's residency.
     */
    public Mono<VpnNodeAssignment> assignNode(String configId, String targetNodeFp,
                                              String serviceSlug, String assignedBy) {
        return configs.findById(configId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException(
                        "VPN config " + configId + " does not exist")))
                // Verify config is active then resolve the node and write the assignment.
                .flatMap(cfg -> assignNodeForConfig(cfg, configId, targetNodeFp, serviceSlug, assignedBy));
    }

    /**
     * Assign a config to a whole DOMAIN (all public pods resident there), optionally
     * narrowed to one {@code serviceSlug}. The target domain MUST equal the config's
     * residency (a config can only egress its own brand). Idempotent on an active (domain,
     * service).
     */
    public Mono<VpnNodeAssignment> assignDomain(String configId, String targetDomain,
                                                String serviceSlug, String assignedBy) {
        return configs.findById(configId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException(
                        "VPN config " + configId + " does not exist")))
                // Verify config is active and domain matches then write the assignment.
                .flatMap(cfg -> assignDomainForConfig(cfg, configId, targetDomain, serviceSlug, assignedBy));
    }

    /** Revoke (un-assign) an assignment by id (CAS audit + gen bump). SUPERADMIN-gated at
     *  the controller. Returns the rows-updated count. */
    public Mono<Long> revokeAssignment(String assignmentId, String revokedBy, PrincipalDomain scope) {
        return assignments.maxGeneration().flatMap(maxGen ->
                assignments.revoke(assignmentId, revokedBy, maxGen + 1, scope)
                        .doOnNext(n -> log.info("[egress-vpn] revoke assignment id={} by={} gen={} rows={}",
                                assignmentId, revokedBy, maxGen + 1, n))
                        // Fast path on an actual deactivate only (the lost-CAS 0 changed nothing).
                        .flatMap(n -> n == 0L ? Mono.just(0L)
                                : labeler.reconcile().thenReturn(n)));
    }

    public Flux<VpnNodeAssignment> listAssignments(PrincipalDomain scope) {
        return assignments.list(scope);
    }

    // ── node report-back ─────────────────────────────────────────────────────────

    /**
     * Record the propagation outcome the node-level reconcile agent reports for ONE node
     * ({@code applied}/{@code failed}/{@code degraded} — never {@code pending}, which only a
     * MUTATION resets). Transitions the {@code propagation_state} of exactly the rows that fed
     * that node's signed export (the {@link VpnExportService} compile predicate): the ACTIVE
     * DEVICE assignments on the fp, the ACTIVE DOMAIN assignments on the node's residency, and
     * the still-active configs they reference. Returns the rows updated. Fail-closed: an
     * unknown fp or a SUPERADMIN-owned node updates NOTHING (0 — a probe learns nothing); an
     * out-of-vocabulary state is a hard {@link IllegalArgumentException} (-> 422).
     */
    public Mono<Long> reportNodeState(String machineKeyFp, String state) {
        if (!VpnConfig.PROP_APPLIED.equals(state) && !VpnConfig.PROP_FAILED.equals(state)
                && !VpnConfig.PROP_DEGRADED.equals(state)) {
            return Mono.error(new IllegalArgumentException(
                    "propagation state must be applied|failed|degraded, not '" + state + "'"));
        }
        return devices.findByMachineKey(machineKeyFp)
                .filter(node -> !node.isSuperadminOwned())
                .flatMap(node -> assignments.listActiveAll().collectList()
                        .flatMap(active -> transitionForNode(node, active, state)))
                .defaultIfEmpty(0L)
                .doOnNext(n -> log.info("[egress-vpn] node report fp={} state={} -> {} row(s)",
                        machineKeyFp, state, n));
    }

    /** Flip the matching assignments + their still-active configs to the reported state. */
    private Mono<Long> transitionForNode(net.hugmesh.adminbff.device.Device node,
                                         List<VpnNodeAssignment> active, String state) {
        List<VpnNodeAssignment> matching = active.stream()
                .filter(a -> (a.isDeviceScoped() && node.machineKeyFp().equals(a.targetNodeId()))
                        || (a.isDomainScoped() && node.domain().equals(a.targetDomain())))
                .toList();
        Set<String> configIds = new LinkedHashSet<>();
        for (VpnNodeAssignment a : matching) configIds.add(a.configId());
        return Flux.fromIterable(matching)
                .concatMap(a -> assignments.updatePropagationState(a.id(), state))
                .reduce(0L, Long::sum)
                .flatMap(an -> Flux.fromIterable(configIds)
                        // A revoked config is skipped — its pending revocation is a MUTATION
                        // outcome the next export propagates, not this report's.
                        .concatMap(id -> configs.findById(id)
                                .filter(VpnConfig::isActive)
                                .flatMap(c -> configs.updatePropagationState(c.id(), state))
                                .defaultIfEmpty(0L))
                        .reduce(0L, Long::sum)
                        .map(cn -> an + cn));
    }

    /** Validate domain + name + config body then idempotently insert a VPN config row. */
    private Mono<VpnConfig> performImportConfig(String domain, String name, String provider,
                                                String configBody, String secretRef, String createdBy) {
        String dom = domain == null ? null : domain.trim();
        if (dom == null || dom.isBlank() || DomainRegistry.DEFAULT_DOMAIN.equals(dom)) {
            return Mono.error(new IllegalArgumentException(
                    "VPN config domain must be a real residency domain, not 'default'/blank [FIX-NODEFAULT]"));
        }
        if (!domainRegistry.isKnownDomain(dom)) {
            return Mono.error(new IllegalArgumentException(
                    "VPN config domain '" + dom + "' is not a known residency domain"));
        }
        if (name == null || name.isBlank()) {
            return Mono.error(new IllegalArgumentException("VPN config name is required"));
        }
        VpnConfigParser.Parsed parsed;
        try {
            parsed = VpnConfigParser.parse(configBody);
        } catch (IllegalArgumentException e) {
            return Mono.error(e); // -> 422
        }
        String cleanName = name.trim();
        final String finalDom = dom;
        return configs.findActiveByName(finalDom, cleanName)
                .doOnNext(existing -> log.info(
                        "[egress-vpn] config {} already active in {} (id={}) — no-op",
                        cleanName, finalDom, existing.id()))
                .switchIfEmpty(Mono.defer(() -> configs.maxGeneration().flatMap(maxGen -> {
                    VpnConfig draft = new VpnConfig(null, finalDom, cleanName, parsed.kind(),
                            provider, parsed.endpoint(), secretRef, VpnConfig.STATE_ACTIVE,
                            createdBy, null, null, null, VpnConfig.PROP_PENDING, maxGen + 1);
                    return configs.insertActive(draft, maxGen + 1)
                            .doOnNext(c -> log.info(
                                    "[egress-vpn] imported config {} kind={} domain={} gen={} (id={})",
                                    c.name(), c.kind(), c.domain(), c.generation(), c.id()))
                            // Runtime delivery leg (fresh import ONLY — never the re-import
                            // no-op): hand the validated bytes to the Secret writer seam.
                            // Best-effort by contract (the writer swallows failures to false);
                            // the row is the committed control record either way.
                            .flatMap(c -> secretWriter
                                    .write(c.secretRef(), c.domain(), c.name(), c.kind(), configBody)
                                    .thenReturn(c));
                })));
    }

    /** Check config is active, resolve the target node, then idempotently insert a node assignment. */
    private Mono<VpnNodeAssignment> assignNodeForConfig(VpnConfig cfg, String configId,
                                                         String targetNodeFp, String serviceSlug,
                                                         String assignedBy) {
        if (!cfg.isActive()) {
            return Mono.error(new IllegalArgumentException(
                    "VPN config " + configId + " is revoked — cannot assign"));
        }
        return devices.findByMachineKey(targetNodeFp)
                .switchIfEmpty(Mono.error(new IllegalArgumentException(
                        "node " + targetNodeFp + " is not registered")))
                .flatMap(node -> insertNodeAssignmentIfAllowed(node, cfg, configId,
                        targetNodeFp, serviceSlug, assignedBy));
    }

    /** Guard superadmin-owned and cross-tenant, then idempotently insert a node-scoped assignment. */
    private Mono<VpnNodeAssignment> insertNodeAssignmentIfAllowed(net.hugmesh.adminbff.device.Device node, VpnConfig cfg,
                                                                   String configId, String targetNodeFp,
                                                                   String serviceSlug, String assignedBy) {
        if (node.isSuperadminOwned()) {
            return Mono.error(new IllegalArgumentException(
                    "cannot assign an egress VPN to a SUPERADMIN-owned node"));
        }
        if (!cfg.domain().equals(node.domain())) {
            return Mono.error(new IllegalArgumentException(
                    "cross-tenant assignment refused: config domain '" + cfg.domain()
                    + "' != node residency '" + node.domain() + "'"));
        }
        String svc = blankToNull(serviceSlug);
        return assignments.findActiveNode(targetNodeFp, svc)
                .doOnNext(existing -> log.info(
                        "[egress-vpn] node assignment already active node={} svc={} (id={}) — no-op",
                        targetNodeFp, svc, existing.id()))
                .switchIfEmpty(Mono.defer(() -> assignments.maxGeneration().flatMap(maxGen -> {
                    VpnNodeAssignment draft = new VpnNodeAssignment(null, configId,
                            VpnNodeAssignment.SCOPE_DEVICE, targetNodeFp, null, svc,
                            VpnNodeAssignment.STATE_ACTIVE, assignedBy, null, null,
                            null, cfg.domain(), VpnNodeAssignment.PROP_PENDING, maxGen + 1);
                    return assignments.insertActive(draft, maxGen + 1)
                            .doOnNext(a -> log.info(
                                    "[egress-vpn] assigned config {} to node {} svc={} domain={} gen={} (id={})",
                                    configId, targetNodeFp, svc, cfg.domain(), a.generation(), a.id()))
                            // Fast path on the fresh activate only (the idempotent no-op
                            // changed nothing to converge).
                            .flatMap(a -> labeler.reconcile().thenReturn(a));
                })));
    }

    /** Check config is active and domain matches, then idempotently insert a domain-scoped assignment. */
    private Mono<VpnNodeAssignment> assignDomainForConfig(VpnConfig cfg, String configId,
                                                           String targetDomain, String serviceSlug,
                                                           String assignedBy) {
        if (!cfg.isActive()) {
            return Mono.error(new IllegalArgumentException(
                    "VPN config " + configId + " is revoked — cannot assign"));
        }
        String td = targetDomain == null ? null : targetDomain.trim();
        if (td == null || td.isBlank() || DomainRegistry.DEFAULT_DOMAIN.equals(td)) {
            return Mono.error(new IllegalArgumentException(
                    "DOMAIN assignment target must be a real residency domain, not 'default'/blank [FIX-NODEFAULT]"));
        }
        if (!cfg.domain().equals(td)) {
            return Mono.error(new IllegalArgumentException(
                    "cross-tenant assignment refused: config domain '" + cfg.domain()
                    + "' != target domain '" + td + "'"));
        }
        String svc = blankToNull(serviceSlug);
        return assignments.findActiveDomain(td, svc)
                .doOnNext(existing -> log.info(
                        "[egress-vpn] domain assignment already active domain={} svc={} (id={}) — no-op",
                        td, svc, existing.id()))
                .switchIfEmpty(Mono.defer(() -> assignments.maxGeneration().flatMap(maxGen -> {
                    VpnNodeAssignment draft = new VpnNodeAssignment(null, configId,
                            VpnNodeAssignment.SCOPE_DOMAIN, null, td, svc,
                            VpnNodeAssignment.STATE_ACTIVE, assignedBy, null, null,
                            null, cfg.domain(), VpnNodeAssignment.PROP_PENDING, maxGen + 1);
                    return assignments.insertActive(draft, maxGen + 1)
                            .doOnNext(a -> log.info(
                                    "[egress-vpn] assigned config {} to domain {} svc={} gen={} (id={})",
                                    configId, td, svc, a.generation(), a.id()))
                            // Fast path on the fresh activate only (the idempotent no-op
                            // changed nothing to converge).
                            .flatMap(a -> labeler.reconcile().thenReturn(a));
                })));
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s.trim();
    }
}
