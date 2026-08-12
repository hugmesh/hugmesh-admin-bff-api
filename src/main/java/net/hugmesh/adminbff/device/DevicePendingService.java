package net.hugmesh.adminbff.device;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds the PENDING pick-list for the machine_key_fp AUTO-CAPTURE flow: the set of
 * headscale-enrolled nodes LEFT-JOINed with {@code device_registry}, so the SUPERADMIN can
 * see which enrolled fingerprints are NOT yet assigned an owner_type/domain/image_type and
 * pick one. Read-only. Headscale is the trust gate (it minted the fingerprints); the fp is an
 * OPAQUE token throughout — this service never types, edits, or normalises it.
 *
 * <h3>Scope</h3>
 * <ul>
 *   <li>SUPERADMIN (unscoped) → every enrolled node, plus its registration status. The
 *       PENDING (unregistered) rows are visible ONLY to a superadmin, because assignment is a
 *       SUPERADMIN mutation.</li>
 *   <li>ADMIN (scoped) → ONLY the already-registered nodes in their own brand (the same
 *       own-domain read wall as the device list). An ADMIN never sees an unassigned enrolled
 *       fingerprint (it has no residency yet, so it cannot belong to their brand).</li>
 * </ul>
 *
 * <h3>⚠ ADVISORY (ships dark)</h3>
 * When {@code app.registry.headscale.enabled=false} (the DEFAULT — no headscale binary in
 * CI/dev) {@link HeadscaleNodesClient#listNodes()} is empty, so the pending list degrades to
 * the REGISTRY-ONLY view (no enrolled-but-unregistered candidates). That is correct
 * fail-soft behaviour: the auto-capture flow simply has nothing to offer until a live control
 * node is wired and the feature flag flipped on.
 */
@Service
public class DevicePendingService {

    private static final Logger log = LoggerFactory.getLogger(DevicePendingService.class);

    private final HeadscaleNodesClient headscale;
    private final DeviceRegistryRepository devices;

    public DevicePendingService(HeadscaleNodesClient headscale, DeviceRegistryRepository devices) {
        this.headscale = headscale;
        this.devices = devices;
    }

    /**
     * The pending pick-list for the given scope. LEFT-JOINs the live headscale node set with
     * the registry by {@code machine_key_fp}: an enrolled fp absent from the registry is a
     * pending candidate ({@code registered=false}, SUPERADMIN-only); an enrolled fp present is
     * shown registered with its stamped residency/owner_type.
     */
    public Flux<PendingNode> pending(PrincipalDomain scope) {
        boolean superadmin = scope == null || !scope.scoped();
        // The registry side of the join: unscoped for a superadmin (every brand), own-brand
        // only for an admin — the SAME read wall as the device list.
        Mono<Map<String, Device>> registryByFp =
                devices.list(scope)
                        .collectMap(Device::machineKeyFp, d -> d, LinkedHashMap::new);

        return registryByFp.flatMapMany(byFp -> headscale.listNodes()
                        .collectList()
                        .map(enrolled -> join(enrolled, byFp, superadmin))
                        .flatMapMany(Flux::fromIterable))
                .doOnComplete(() -> log.debug("[device-pending] pick-list built (superadmin={})", superadmin));
    }

    private List<PendingNode> join(List<HeadscaleNode> enrolled, Map<String, Device> byFp, boolean superadmin) {
        List<PendingNode> out = new ArrayList<>();
        Map<String, Boolean> seen = new LinkedHashMap<>();
        // (1) Every enrolled headscale node, marked registered iff present in the (scoped)
        //     registry view. Unregistered candidates are SUPERADMIN-only.
        for (HeadscaleNode n : enrolled) {
            seen.put(n.machineKeyFp(), Boolean.TRUE);
            Device d = byFp.get(n.machineKeyFp());
            if (d != null) {
                out.add(new PendingNode(n.machineKeyFp(), preferRegistryHost(n, d), n.user(),
                        n.meshId(), true, d.domain(), d.ownerType()));
            } else if (superadmin) {
                out.add(new PendingNode(n.machineKeyFp(), n.hostname(), n.user(),
                        n.meshId(), false, null, null));
            }
        }
        // (2) Registered rows the admin can read that headscale did NOT report (offline /
        //     deregistered upstream) — still surfaced as registered so the console is complete.
        for (Device d : byFp.values()) {
            if (!seen.containsKey(d.machineKeyFp())) {
                out.add(new PendingNode(d.machineKeyFp(), d.hostname(), null,
                        d.meshId(), true, d.domain(), d.ownerType()));
            }
        }
        return out;
    }

    private static String preferRegistryHost(HeadscaleNode n, Device d) {
        return d.hostname() != null && !d.hostname().isBlank() ? d.hostname() : n.hostname();
    }
}
