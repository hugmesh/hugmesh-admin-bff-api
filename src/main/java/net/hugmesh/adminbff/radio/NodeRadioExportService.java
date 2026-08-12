package net.hugmesh.adminbff.radio;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.device.RegistrySigner;
import net.hugmesh.adminbff.radio.RadioExportModels.RadioEntry;
import net.hugmesh.adminbff.radio.RadioExportModels.RadioExportBody;
import net.hugmesh.adminbff.radio.RadioExportModels.SignedRadioExport;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Builds the SIGNED PER-NODE node-radio export — REPRODUCES
 * {@link net.hugmesh.adminbff.storage.NodeStorageExportService#exportNode} EXACTLY:
 * the same {@code machine_key_fp -> node} resolution (UNSCOPED, fail-closed on an unknown
 * fingerprint), the same canonical-bytes header, the same detached Ed25519 signature
 * (reusing {@link RegistrySigner}), and the same monotonic {@code generation} a node's
 * rollback guard reads. The CONSUMER is the FUTURE on-node meshbridge reconcile agent (NOT
 * in this repo): it fetches its OWN export and learns ONLY its own radios — never another
 * node's / another domain's radios [CONFIDENTIALITY].
 *
 * <h3>FAIL-CLOSED on an unknown fingerprint</h3>
 * An UNKNOWN fp yields an EMPTY (but signed) body over an empty node header — NOT an error,
 * so a probe of an unknown fp leaks NOTHING (no radio count, no node id, no host). The
 * radios repo is NEVER even read for an unknown node (no over-fetch), exactly as the
 * storage export's per-node path does.
 */
@Service
public class NodeRadioExportService {

    private static final Logger log = LoggerFactory.getLogger(NodeRadioExportService.class);

    private final DeviceRegistryRepository devices;
    private final RadioDeviceRepository radios;
    private final RegistrySigner signer;

    public NodeRadioExportService(DeviceRegistryRepository devices, RadioDeviceRepository radios,
                                  RegistrySigner signer) {
        this.devices = devices;
        this.radios = radios;
        this.signer = signer;
    }

    /**
     * Build + sign the PER-NODE export for ONE device, addressed by its stable
     * {@code machine_key_fp}. The signed body carries ONLY the ACTIVE radios attached to
     * THAT node. UNSCOPED resolution + FAIL-CLOSED: an unknown fp yields an empty signed
     * body, never a leaky error.
     *
     * TODO: no consumer of this export exists yet — the merged meshbridge daemon
     * (hugmesh-generator PR #374) reads a separate, static, manually-edited devices
     * ConfigMap instead. Wiring a reconcile agent to read this export and write that
     * ConfigMap is the documented follow-up (see meshbridge/devices-configmap.yaml).
     */
    public Mono<SignedRadioExport> exportNode(String machineKeyFp) {
        return devices.findByMachineKey(machineKeyFp)
                .flatMap(node -> radios.listActiveForDevice(node.id()).collectList()
                        .map(rows -> sign(compile(node, rows))))
                // fail-closed: unknown fp -> empty signed body over an empty node header.
                .switchIfEmpty(Mono.fromSupplier(() -> sign(emptyBody())));
    }

    /**
     * Compile the per-node body deterministically (stable radio ordering) so the
     * content-hash + signature are reproducible. {@code generation} is the MAX across the
     * node's radios — the agent accepts ONLY a strictly-higher generation than its
     * last-good cache (rollback guard). Pure + deterministic (no IO).
     */
    private RadioExportBody compile(Device node, List<RadioDevice> rows) {
        long maxGen = 0L;
        List<RadioEntry> entries = new ArrayList<>(rows.size());
        for (RadioDevice r : rows) {
            maxGen = Math.max(maxGen, r.generation());
            entries.add(new RadioEntry(r.radioId(), r.transport(), r.serialPath(), r.host(),
                    r.port(), r.topicRoot(), r.channelName(), r.gatewayNodeId(), r.meshChannel()));
        }
        entries.sort(Comparator.comparing(RadioEntry::radioId));
        return new RadioExportBody(node.machineKeyFp(), maxGen, List.copyOf(entries));
    }

    /** The empty (unknown-fp) body — empty node header, no radios (fail-closed). */
    private static RadioExportBody emptyBody() {
        return new RadioExportBody("", 0L, List.of());
    }

    /** Wrap a compiled body in the signed envelope: SHA-256 content-hash + detached Ed25519
     *  over the canonical body bytes. Unsigned when no key (consumer fail-closes). */
    SignedRadioExport sign(RadioExportBody body) {
        byte[] canonical = canonicalBytes(body);
        String hash = RegistrySigner.contentHash(canonical);
        String sig = signer.sign(canonical);
        if (sig == null) {
            log.warn("[node-radio-export] node={} gen={} served UNSIGNED (no signing key) — "
                    + "consumers fail closed", body.nodeFp(), body.generation());
        }
        return new SignedRadioExport(body, hash, sig, signer.publicKeyBase64(), sig != null);
    }

    /**
     * The canonical, deterministic byte encoding the content-hash + signature cover — the
     * SAME line-oriented form as the device/storage exports (NOT JSON, to avoid serializer
     * ordering ambiguity). The same bytes the meshbridge agent recomputes to verify.
     */
    static byte[] canonicalBytes(RadioExportBody body) {
        StringBuilder sb = new StringBuilder();
        sb.append("v1\n");
        sb.append("node=").append(nz(body.nodeFp())).append('\n');
        sb.append("generation=").append(body.generation()).append('\n');
        for (RadioEntry r : body.radios()) {
            sb.append("radio=").append(nz(r.radioId()))
              .append('\t').append("transport=").append(nz(r.transport()))
              .append('\t').append("serial=").append(nz(r.serialPath()))
              .append('\t').append("host=").append(nz(r.host()))
              .append('\t').append("port=").append(r.port() == null ? "" : r.port())
              .append('\t').append("topic=").append(nz(r.topicRoot()))
              .append('\t').append("channelName=").append(nz(r.channelName()))
              .append('\t').append("gateway=").append(nz(r.gatewayNodeId()))
              .append('\t').append("channel=").append(r.meshChannel())
              .append('\n');
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
