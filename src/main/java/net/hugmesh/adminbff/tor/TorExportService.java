package net.hugmesh.adminbff.tor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.capability.DomainCapability;
import net.hugmesh.adminbff.capability.DomainCapabilityRepository;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.RegistrySigner;
import net.hugmesh.adminbff.tor.TorExportModels.SignedTorExport;
import net.hugmesh.adminbff.tor.TorExportModels.TorExportBody;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.TreeSet;

/**
 * Builds the SIGNED PER-NODE Tor export — the runtime writer of a node's
 * {@code /etc/hugmesh/tor/upstream} and {@code /etc/hugmesh/tor/domains}
 * (hugmesh-admin-bff-api#108). CLONES {@link net.hugmesh.adminbff.egressvpn.VpnExportService}:
 * a pure deterministic {@link #compile} plus a detached-Ed25519 {@link #sign} over canonical
 * line-oriented UTF-8 bytes, reusing the same {@link RegistrySigner} bean.
 *
 * <h3>What the body carries</h3>
 * <ul>
 *   <li><b>upstream</b> — PER NODE, from {@code tor_node_config}. No row = unmanaged.</li>
 *   <li><b>domains</b> — MESH-WIDE, from the {@link DomainCapability#TOR_ONION} gate rows.
 *       Unmanaged until a SUPERADMIN writes the {@code ' global'} row; then the list is the
 *       domains whose row is active ({@code granted && enabled}) when the global row is
 *       granted, and empty when it is not (the kill switch). {@code default} is never
 *       listed: the primary onion already serves it. A domain that is not a valid node slug
 *       is left out with a warning, because the node agent would refuse it.</li>
 * </ul>
 *
 * <h3>Fail-closed</h3>
 * An UNKNOWN fingerprint gets an EMPTY signed body (empty node, generation 0, nothing
 * managed), never an error, so a probe learns nothing and the agent changes nothing. Unlike
 * the egress-VPN export, a SUPERADMIN-owned node is NOT excluded: the ingress-edge node that
 * runs tor is normally a core node. Unsigned (no key configured) = the agent fails closed.
 */
@Service
public class TorExportService {

    private static final Logger log = LoggerFactory.getLogger(TorExportService.class);

    private final DeviceRegistryRepository devices;
    private final TorNodeConfigRowRepository configs;
    private final DomainCapabilityRepository capabilities;
    private final RegistrySigner signer;

    public TorExportService(DeviceRegistryRepository devices, TorNodeConfigRowRepository configs,
                            DomainCapabilityRepository capabilities, RegistrySigner signer) {
        this.devices = devices;
        this.configs = configs;
        this.capabilities = capabilities;
        this.signer = signer;
    }

    /** Build + sign the export for the node addressed by its {@code machine_key_fp}. */
    public Mono<SignedTorExport> exportNode(String machineKeyFp) {
        return devices.findByMachineKey(machineKeyFp)
                .flatMap(node -> Mono.zip(
                                configs.findByMachineKeyFp(node.machineKeyFp())
                                        .map(TorNodeConfigRow::toDomain)
                                        .map(Optional::of)
                                        .defaultIfEmpty(Optional.empty()),
                                capabilities.listAll()
                                        .filter(c -> DomainCapability.TOR_ONION.equals(c.capability()))
                                        .collectList())
                        .map(t -> sign(compile(node.machineKeyFp(), t.getT1().orElse(null), t.getT2()))))
                // fail-closed: unknown fp -> empty signed body, nothing managed.
                .switchIfEmpty(Mono.fromSupplier(() -> sign(emptyBody())));
    }

    /**
     * Pure, deterministic compile. {@code torOnionRows} are the {@code domain_capability}
     * rows whose capability is {@link DomainCapability#TOR_ONION} (any other row is ignored
     * defensively).
     */
    static TorExportBody compile(String fp, TorNodeConfig config, List<DomainCapability> torOnionRows) {
        boolean upstreamManaged = config != null && config.upstreamManaged();
        String upstream = upstreamManaged && config.upstream() != null ? config.upstream() : "";

        DomainCapability global = null;
        long capGen = 0L;
        for (DomainCapability c : torOnionRows) {
            if (!DomainCapability.TOR_ONION.equals(c.capability())) continue;
            capGen = Math.max(capGen, c.generation());
            if (DomainCapability.GLOBAL_DOMAIN.equals(c.domain())) global = c;
        }
        boolean domainsManaged = global != null;
        TreeSet<String> slugs = new TreeSet<>();
        if (domainsManaged && global.granted()) {
            for (DomainCapability c : torOnionRows) {
                if (!DomainCapability.TOR_ONION.equals(c.capability())) continue;
                if (DomainCapability.GLOBAL_DOMAIN.equals(c.domain())) continue;
                if (!c.active()) continue;
                if (TorOnionRules.DEFAULT_DOMAIN.equals(c.domain())) continue;
                if (!TorOnionRules.isSlug(c.domain())) {
                    log.warn("[tor-export] domain '{}' has an active tor-onion row but is not a node "
                            + "slug ([a-z0-9][a-z0-9-]{{0,62}}) — left out of the export", c.domain());
                    continue;
                }
                slugs.add(c.domain());
            }
        }
        long generation = (config == null ? 0L : config.configGeneration()) + capGen;
        return new TorExportBody(fp, generation, upstreamManaged, upstream, domainsManaged,
                List.copyOf(slugs));
    }

    /** The fail-closed body for an unknown fingerprint: nothing managed. */
    static TorExportBody emptyBody() {
        return new TorExportBody("", 0L, false, "", false, List.of());
    }

    /** Wrap a body in the signed envelope (SHA-256 content-hash + detached Ed25519). */
    SignedTorExport sign(TorExportBody body) {
        byte[] canonical = canonicalBytes(body);
        String hash = RegistrySigner.contentHash(canonical);
        String sig = signer.sign(canonical);
        if (sig == null) {
            log.warn("[tor-export] node={} gen={} served UNSIGNED (no signing key) — agent fails closed",
                    body.node(), body.generation());
        }
        return new SignedTorExport(body, hash, sig, signer.publicKeyBase64(), sig != null);
    }

    /**
     * The canonical bytes the content-hash and signature cover, and that the node agent
     * recomputes to verify (NOT JSON, so there is no field-order ambiguity):
     * <pre>
     *   v1-tor\n
     *   node=&lt;machineKeyFp&gt;\n
     *   generation=&lt;long&gt;\n
     *   upstream-managed=&lt;true|false&gt;\n
     *   upstream=&lt;host:port or empty&gt;\n
     *   domains-managed=&lt;true|false&gt;\n
     *   domain=&lt;slug&gt;\n   (one per slug, sorted)
     * </pre>
     */
    static byte[] canonicalBytes(TorExportBody body) {
        StringBuilder sb = new StringBuilder();
        sb.append("v1-tor\n");
        sb.append("node=").append(nz(body.node())).append('\n');
        sb.append("generation=").append(body.generation()).append('\n');
        sb.append("upstream-managed=").append(body.upstreamManaged()).append('\n');
        sb.append("upstream=").append(nz(body.upstream())).append('\n');
        sb.append("domains-managed=").append(body.domainsManaged()).append('\n');
        for (String slug : body.domains()) {
            sb.append("domain=").append(slug).append('\n');
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
