package net.hugmesh.adminbff.radio;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.regex.Pattern;

/**
 * Write/read surface for NODE RADIOS — the Meshtastic LoRa radio an operator ATTACHES to a
 * specific mesh node so the meshbridge optional service can reach the LoRa mesh through
 * that node ({@code node_radio_device}, schema 300). CLONES the
 * {@link net.hugmesh.adminbff.storage.NodeStorageService} desired-state idioms
 * (resolve the target FIRST, idempotent findActive-then-insert, CAS-detach audit, monotonic
 * generation, residency-stamped domain) INCLUDING its deliberate DIVERGENCE: the OWNERSHIP
 * ALLOW/DENY matrix.
 *
 * <h3>OWNERSHIP ALLOW/DENY matrix (the load-bearing security)</h3>
 * Radios are ADMIN-CAPABLE (not superadmin-only, unlike SSH licensing) but OWNERSHIP-gated.
 * For a caller {@link PrincipalDomain} acting on a resolved node {@link Device}:
 * <ul>
 *   <li><b>SUPERADMIN</b> ({@code scope.superadmin()}) — UNRESTRICTED: any node, any
 *       domain, ADMIN- or SUPERADMIN-owned. ALLOW.</li>
 *   <li><b>ADMIN</b> ({@code scope.scoped()}) acting on an <b>ADMIN-owned</b> node in their
 *       <b>own residency domain</b> ({@code device.domain == scope.domain}) — ALLOW.</li>
 *   <li><b>ADMIN</b> acting on a <b>SUPERADMIN-owned</b> node — DENY (those are
 *       SUPERADMIN-only, regardless of domain).</li>
 *   <li><b>ADMIN</b> acting on an ADMIN-owned node in <b>another</b> domain — DENY
 *       (cross-domain).</li>
 * </ul>
 * A DENY is a {@link RadioAccessDeniedException} (controller -&gt; 403). The node is
 * resolved FIRST so the gate fires before ANY write and the radio {@code domain} is
 * stamped from the device's RESIDENCY [FIX-NODEFAULT], never the caller.
 *
 * <h3>Per-transport shape matrix (mixed shapes rejected 422)</h3>
 * An attach is rejected (422) when the body's columns do not match its transport EXACTLY
 * (the DB {@code ck_node_radio_device_shape} CHECK is the backstop):
 * <ul>
 *   <li>{@code serial} — {@code serialPath} REQUIRED; host/port/topicRoot/channelName/
 *       gatewayNodeId must be ABSENT;</li>
 *   <li>{@code tcp} — {@code host} REQUIRED, {@code port} defaulted to the Meshtastic TCP
 *       API port {@value #DEFAULT_TCP_PORT} when omitted; serialPath/topicRoot/channelName/
 *       gatewayNodeId must be ABSENT;</li>
 *   <li>{@code mqtt} — {@code host}, {@code port}, {@code topicRoot} and
 *       {@code channelName} REQUIRED, {@code gatewayNodeId} OPTIONAL; serialPath must be
 *       ABSENT.</li>
 * </ul>
 * Field FORMATS (the serial-path / host / port / radio-id / gateway-id patterns) are bean
 * validation on the DTO (a malformed field is a clean 400 before the service is reached);
 * this matrix is the CROSS-FIELD semantic gate (422), mirroring how node-storage splits
 * bean-400s from service-422s.
 */
@Service
public class NodeRadioService {

    private static final Logger log = LoggerFactory.getLogger(NodeRadioService.class);

    /** The Meshtastic TCP API port a LoRa-WiFi radio listens on — the {@code tcp} default. */
    public static final int DEFAULT_TCP_PORT = 4403;

    /** hostname (RFC-1123 labels) or dotted IPv4 — the DTO @Pattern's semantic twin, re-run
     *  here so a programmatic caller cannot bypass the bean layer. */
    static final Pattern HOST_PATTERN =
            Pattern.compile("^[A-Za-z0-9]([A-Za-z0-9-]{0,62})?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,62})?)*$");

    private final RadioDeviceRepository radios;
    private final DeviceRegistryRepository devices;

    public NodeRadioService(RadioDeviceRepository radios, DeviceRegistryRepository devices) {
        this.radios = radios;
        this.devices = devices;
    }

    // ════════════════════════ OWNERSHIP ALLOW/DENY ═════════════════════════════

    /**
     * The ownership ALLOW/DENY predicate (pure — unit-testable in isolation). Returns null
     * when ALLOWED, or a human-readable DENY reason. SUPERADMIN is unrestricted; an ADMIN is
     * allowed ONLY on an ADMIN-owned node in their own residency domain.
     */
    static String denyReason(PrincipalDomain scope, Device device) {
        if (scope != null && scope.superadmin()) {
            return null;   // SUPERADMIN: unrestricted
        }
        // ADMIN (scoped) path.
        if (device.isSuperadminOwned()) {
            return "node " + device.id() + " is SUPERADMIN-owned — only a SUPERADMIN may "
                    + "manage its radios";
        }
        String callerDomain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
        if (!device.domain().equals(callerDomain)) {
            return "node " + device.id() + " is resident in domain '" + device.domain()
                    + "' — an ADMIN may only manage radios on own-domain nodes (caller domain '"
                    + callerDomain + "')";
        }
        return null;   // ADMIN: own-domain, ADMIN-owned -> ALLOW
    }

    /** Resolve the node by id (fail with 422 IllegalArgumentException if unknown), then
     *  apply the ownership gate (fail with 403 RadioAccessDeniedException on DENY),
     *  returning the resolved device for residency-stamping. */
    private Mono<Device> resolveAndGate(String deviceId, PrincipalDomain scope) {
        return devices.findById(deviceId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException(
                        "node " + deviceId + " is not registered")))
                .flatMap(device -> {
                    String deny = denyReason(scope, device);
                    if (deny != null) {
                        return Mono.error(new RadioAccessDeniedException(deny));
                    }
                    return Mono.just(device);
                });
    }

    // ════════════════════════ per-transport shape matrix ═══════════════════════

    /**
     * Normalise + validate the (transport, columns) shape and return the shape to persist
     * (the {@code tcp} port default is applied here). Throws
     * {@link IllegalArgumentException} (-&gt; 422) on a MIXED shape — a column that belongs
     * to another transport is present, or a required column is missing. Pure (no IO),
     * unit-testable in isolation.
     */
    static TransportShape validateShape(String transport, String serialPath, String host,
                                        Integer port, String topicRoot, String channelName,
                                        String gatewayNodeId) {
        String serial = blankToNull(serialPath);
        String h = blankToNull(host);
        String topic = blankToNull(topicRoot);
        String channel = blankToNull(channelName);
        String gateway = blankToNull(gatewayNodeId);
        switch (transport == null ? "" : transport) {
            case RadioDevice.TRANSPORT_SERIAL -> {
                require(serial != null, "serial transport requires serialPath");
                reject(h != null || port != null, "serial transport must not carry host/port");
                reject(topic != null || channel != null || gateway != null,
                        "serial transport must not carry topicRoot/channelName/gatewayNodeId");
                return new TransportShape(RadioDevice.TRANSPORT_SERIAL, serial, null, null,
                        null, null, null);
            }
            case RadioDevice.TRANSPORT_TCP -> {
                require(h != null, "tcp transport requires host");
                reject(serial != null, "tcp transport must not carry serialPath");
                reject(topic != null || channel != null || gateway != null,
                        "tcp transport must not carry topicRoot/channelName/gatewayNodeId");
                int p = port == null ? DEFAULT_TCP_PORT : port;   // Meshtastic TCP API default
                require(HOST_PATTERN.matcher(h).matches(), "host must be a hostname or IPv4");
                return new TransportShape(RadioDevice.TRANSPORT_TCP, null, h, p, null, null, null);
            }
            case RadioDevice.TRANSPORT_MQTT -> {
                require(h != null, "mqtt transport requires host");
                require(port != null, "mqtt transport requires port");
                require(topic != null, "mqtt transport requires topicRoot");
                require(channel != null, "mqtt transport requires channelName");
                reject(serial != null, "mqtt transport must not carry serialPath");
                require(HOST_PATTERN.matcher(h).matches(), "host must be a hostname or IPv4");
                return new TransportShape(RadioDevice.TRANSPORT_MQTT, null, h, port, topic,
                        channel, gateway);
            }
            default -> throw new IllegalArgumentException(
                    "transport must be one of serial|tcp|mqtt (got '" + transport + "')");
        }
    }

    /** The validated, normalised per-transport column shape an attach persists. */
    record TransportShape(String transport, String serialPath, String host, Integer port,
                          String topicRoot, String channelName, String gatewayNodeId) {}

    private static void require(boolean ok, String message) {
        if (!ok) throw new IllegalArgumentException(message);
    }

    private static void reject(boolean bad, String message) {
        if (bad) throw new IllegalArgumentException(message + " (mixed transport shape)");
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }

    // ════════════════════════ radio attach / detach ════════════════════════════

    /**
     * Idempotently ATTACH a radio to {@code deviceId}. Resolves the node FIRST →
     * ownership gate → per-transport shape matrix → stamps the radio {@code domain} from
     * the device's residency [FIX-NODEFAULT]. An existing active (device, radioId) row is
     * returned unchanged (the no-op attach); otherwise a new active row is written at the
     * next monotonic generation.
     */
    public Mono<RadioDevice> attachRadio(String deviceId, String transport, String serialPath,
                                         String host, Integer port, String topicRoot,
                                         String channelName, String gatewayNodeId,
                                         String radioId, int meshChannel,
                                         PrincipalDomain scope, String createdBy) {
        if (meshChannel < 0 || meshChannel > 7) {
            return Mono.error(new IllegalArgumentException("meshChannel must be 0..7"));
        }
        final TransportShape shape;
        try {
            shape = validateShape(transport, serialPath, host, port, topicRoot, channelName,
                    gatewayNodeId);
        } catch (IllegalArgumentException e) {
            return Mono.error(e);
        }
        // Gate on device ownership then idempotently insert a new radio row.
        return resolveAndGate(deviceId, scope)
                .flatMap(device -> attachRadioForDevice(device, deviceId, shape, radioId,
                        meshChannel, createdBy));
    }

    /** Resolve the device, gate ownership, then idempotently insert a radio row for it. */
    private Mono<RadioDevice> attachRadioForDevice(Device device, String deviceId,
                                                   TransportShape shape, String radioId,
                                                   int meshChannel, String createdBy) {
        return radios.findActiveRadio(deviceId, radioId)
                .doOnNext(existing -> log.info(
                        "[node-radios] radio already active for device {} radio {} (id={}) — no-op",
                        deviceId, radioId, existing.id()))
                // Insert a new radio if none exists yet for this device+radioId.
                .switchIfEmpty(Mono.defer(() -> insertRadioRow(device, deviceId, shape, radioId,
                        meshChannel, createdBy)));
    }

    /** Allocate a generation slot and insert a new radio row for the device+radioId. */
    private Mono<RadioDevice> insertRadioRow(Device device, String deviceId, TransportShape shape,
                                             String radioId, int meshChannel, String createdBy) {
        return radios.maxGeneration().flatMap(maxGen -> {
            RadioDevice draft = new RadioDevice(null, deviceId, shape.transport(),
                    shape.serialPath(), shape.host(), shape.port(), shape.topicRoot(),
                    shape.channelName(), shape.gatewayNodeId(), radioId, meshChannel,
                    RadioDevice.STATE_ACTIVE, device.domain(), RadioDevice.PROP_PENDING,
                    maxGen + 1, createdBy, null, null, null);
            return insertAndLogRadio(draft, maxGen + 1);
        });
    }

    private Mono<RadioDevice> insertAndLogRadio(RadioDevice draft, long generation) {
        return radios.insertActive(draft, generation)
                .doOnNext(r -> log.info(
                        "[node-radios] attached radio {} ({}) device {} domain={} channel={} gen={} (id={})",
                        draft.radioId(), draft.transport(), draft.deviceId(), draft.domain(),
                        draft.meshChannel(), r.generation(), r.id()));
    }

    /**
     * DETACH a radio by row id (CAS active->detached at the next generation). Resolves the
     * radio's node FIRST → ownership gate. Returns rows-updated (1 = detached, 0 = already
     * detached/absent).
     */
    public Mono<Long> detachRadio(String radioId, PrincipalDomain scope, String detachedBy) {
        return radios.findById(radioId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException(
                        "radio " + radioId + " not found")))
                // Gate on device ownership, then CAS to detached.
                .flatMap(radio -> resolveAndGate(radio.deviceId(), scope)
                        .then(radios.maxGeneration())
                        .flatMap(maxGen -> radios.detach(radioId, detachedBy, maxGen + 1, scope)
                                .doOnNext(n -> log.info(
                                        "[node-radios] detach radio id={} by={} gen={} rows={}",
                                        radioId, detachedBy, maxGen + 1, n))));
    }

    // ════════════════════════ read (admin surface, scoped) ═════════════════════

    /** Radios VISIBLE to the given tenant scope — ADMIN own-domain only, SUPERADMIN all. */
    public Flux<RadioDevice> listRadios(PrincipalDomain scope) {
        return radios.list(scope);
    }
}
