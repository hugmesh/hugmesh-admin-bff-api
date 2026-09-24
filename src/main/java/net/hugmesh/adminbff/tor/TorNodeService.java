package net.hugmesh.adminbff.tor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The node Tor contract's admin-bff half (hugmesh-admin-bff-api#108), except the signed
 * export ({@link TorExportService}):
 * <ul>
 *   <li>{@link #report} — a node's exported onion hostnames, received over the
 *       {@code /bff/internal/**} SERVICE channel (the transport the device-enrollment
 *       self-report already uses for node facts). Every value is validated against the
 *       shape the node agent writes, then stored as telemetry.</li>
 *   <li>{@link #list} — the operator view: each node's {@code {primary, domains}} joined
 *       with the registry and its desired state; redacted for a domain ADMIN.</li>
 *   <li>{@link #setUpstream} — the SUPERADMIN write of a node's managed upstream, which
 *       the export then carries to {@code /etc/hugmesh/tor/upstream}.</li>
 * </ul>
 */
@Service
public class TorNodeService {

    private static final Logger log = LoggerFactory.getLogger(TorNodeService.class);

    private final TorNodeReportRowRepository reports;
    private final TorNodeConfigRowRepository configs;
    private final DeviceRegistryRepository devices;

    public TorNodeService(TorNodeReportRowRepository reports, TorNodeConfigRowRepository configs,
                          DeviceRegistryRepository devices) {
        this.reports = reports;
        this.configs = configs;
        this.devices = devices;
    }

    /**
     * Record a node's exported onions (INSERT or REPLACE by fingerprint). {@code primary}
     * may be {@code null} (not minted yet); {@code domains} may be {@code null} or empty.
     * A value the node agent could not have exported is refused with a 422 and nothing is
     * written. Returns the resulting report.
     */
    public Mono<TorNodeReport> report(String machineKeyFp, String primary, Map<String, String> domains) {
        String bad = reportRefusal(primary, domains);
        if (bad != null) {
            return Mono.error(ApiException.unprocessable(bad));
        }
        String encoded = TorNodeReport.encodeDomainOnions(domains);
        return reports.upsert(machineKeyFp, primary, encoded)
                .then(reports.findByMachineKeyFp(machineKeyFp))
                .map(TorNodeReportRow::toDomain);
    }

    /** Why this report cannot be stored, or {@code null} when it can. */
    static String reportRefusal(String primary, Map<String, String> domains) {
        if (primary != null && !TorOnionRules.isOnionV3(primary)) {
            return "primary must be a Tor v3 onion hostname (56 base32 characters + .onion)";
        }
        if (domains == null) {
            return null;
        }
        if (domains.size() > TorOnionRules.MAX_DOMAINS) {
            return "at most " + TorOnionRules.MAX_DOMAINS + " domain onions per node";
        }
        for (Map.Entry<String, String> e : domains.entrySet()) {
            if (!TorOnionRules.isSlug(e.getKey())) {
                return "domain slug '" + e.getKey() + "' is not [a-z0-9][a-z0-9-]{0,62}";
            }
            if (!TorOnionRules.isOnionV3(e.getValue())) {
                return "the onion for domain '" + e.getKey()
                        + "' is not a Tor v3 onion hostname (56 base32 characters + .onion)";
            }
        }
        return null;
    }

    /**
     * The SUPERADMIN write: manage this node's {@code /etc/hugmesh/tor/upstream}.
     * {@code upstream} is a {@code host:port} the node agent accepts, or {@code null} for
     * the agent's built-in default (the agent then removes the file). The node must be in
     * {@code device_registry}: a config for a fingerprint no node answers to is refused
     * (422), so a typo cannot silently configure nothing.
     */
    public Mono<TorNodeConfig> setUpstream(String machineKeyFp, String upstream, String actor) {
        if (upstream != null) {
            var refusal = TorOnionRules.upstreamRefusal(upstream);
            if (refusal.isPresent()) {
                return Mono.error(ApiException.unprocessable(refusal.get()));
            }
        }
        return devices.findByMachineKey(machineKeyFp)
                .switchIfEmpty(Mono.error(ApiException.unprocessable(
                        "no registered node has this machine key fingerprint")))
                .flatMap(node -> configs.upsertUpstream(node.machineKeyFp(), upstream, actor))
                .then(configs.findByMachineKeyFp(machineKeyFp))
                .map(TorNodeConfigRow::toDomain)
                .doOnNext(c -> log.warn("[tor] upstream for node {} set by {} -> {} (generation {})",
                        c.machineKeyFp(), actor,
                        c.upstream() == null ? "<agent default>" : c.upstream(),
                        c.configGeneration()));
    }

    /**
     * The operator view, one row per fingerprint that has reported or been configured.
     * SUPERADMIN: every row, every field. Domain ADMIN: only registered nodes, redacted by
     * {@link #redactFor}; rows with nothing left to show are dropped.
     */
    public Flux<TorNodeView> list(PrincipalDomain scope) {
        return Mono.zip(
                        reports.findByOrderByMachineKeyFpAsc().map(TorNodeReportRow::toDomain).collectList(),
                        configs.findByOrderByMachineKeyFpAsc().map(TorNodeConfigRow::toDomain).collectList(),
                        devices.listAll().collectList())
                .flatMapMany(t -> Flux.fromIterable(join(t.getT1(), t.getT2(), t.getT3())))
                .concatMap(v -> scope.superadmin()
                        ? Mono.just(v)
                        : Mono.justOrEmpty(redactFor(v, scope.domain())));
    }

    /** Pure join of reports + configs + registry into views, sorted by fingerprint. */
    static List<TorNodeView> join(List<TorNodeReport> reportRows, List<TorNodeConfig> configRows,
                                  List<Device> registry) {
        Map<String, TorNodeReport> byReport = reportRows.stream()
                .collect(Collectors.toMap(TorNodeReport::machineKeyFp, Function.identity(), (a, b) -> a));
        Map<String, TorNodeConfig> byConfig = configRows.stream()
                .collect(Collectors.toMap(TorNodeConfig::machineKeyFp, Function.identity(), (a, b) -> a));
        Map<String, Device> byFp = registry.stream()
                .collect(Collectors.toMap(Device::machineKeyFp, Function.identity(), (a, b) -> a));
        TreeSet<String> fps = new TreeSet<>(byReport.keySet());
        fps.addAll(byConfig.keySet());
        List<TorNodeView> out = new ArrayList<>();
        for (String fp : fps) {
            TorNodeReport r = byReport.get(fp);
            TorNodeConfig c = byConfig.get(fp);
            Device d = byFp.get(fp);
            out.add(new TorNodeView(
                    fp,
                    d == null ? null : d.hostname(),
                    d == null ? null : d.domain(),
                    d != null,
                    r == null ? null : r.primaryOnion(),
                    r == null ? Map.of() : r.domainOnions(),
                    c != null && c.upstreamManaged(),
                    c == null ? null : c.upstream(),
                    c == null ? 0L : c.configGeneration(),
                    r == null ? null : r.lastReportedAt(),
                    r == null ? 0L : r.reportCount()));
        }
        return out;
    }

    /**
     * What a domain ADMIN of {@code domain} may see of one row, or {@code null} for nothing.
     * Only a REGISTERED node's report counts (an unregistered fingerprint is unverified
     * telemetry). The admin sees the onion the node exports for their own slug, and the
     * primary onion only when their domain is {@code default} (the primary is the default
     * brand's door). Node identity, residency and routing are never shown to an ADMIN.
     */
    static TorNodeView redactFor(TorNodeView v, String domain) {
        if (!v.registered() || domain == null || domain.isBlank()) {
            return null;
        }
        String own = v.domains().get(domain);
        String primary = TorOnionRules.DEFAULT_DOMAIN.equals(domain) ? v.primary() : null;
        if (own == null && primary == null) {
            return null;
        }
        Map<String, String> domains = new TreeMap<>();
        if (own != null) domains.put(domain, own);
        return new TorNodeView(null, null, null, true, primary, domains, false, null, 0L,
                v.lastReportedAt(), 0L);
    }
}
