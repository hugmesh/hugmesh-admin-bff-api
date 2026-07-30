package systems.hugmesh.adminbff.radio;

import java.time.Instant;

/**
 * A single {@code node_radio_device} row — a Meshtastic LoRa RADIO an operator ATTACHED to
 * one mesh node so the meshbridge optional service (the mesh&lt;-&gt;Matrix bridge) can reach
 * the LoRa mesh THROUGH that node (schema in Liquibase
 * {@code db/changelog/300-node-radio-device.xml}). CLONES the
 * {@link systems.hugmesh.adminbff.storage.StoragePool} record shape + idioms.
 *
 * <p>A radio is NODE-PINNED: the on-node meshbridge reconcile agent bridges exactly the
 * radios pinned to {@link #deviceId()}. The radio's RESIDENCY ({@link #domain()}) + the
 * node's {@code owner_type} are read THROUGH the FK'd device — the service stamps domain
 * from the device's residency [FIX-NODEFAULT] and gates the ownership ALLOW/DENY matrix on
 * the device's {@code owner_type}.
 *
 * <ul>
 *   <li>{@code deviceId} — the node the radio is attached to / reachable from (FK ->
 *       device_registry).</li>
 *   <li>{@code transport} — HOW the node reaches the radio: {@code serial} (a USB-serial
 *       Meshtastic device on that node), {@code tcp} (a LoRa-WiFi radio dialled over the
 *       Meshtastic TCP API, default port 4403), or {@code mqtt} (a WAN-linked /
 *       LoRaWAN-gateway-style mesh reached via a Meshtastic MQTT broker — JSON
 *       integration, default port 1883 — NOT a locally attached radio).</li>
 *   <li>{@code serialPath} — serial ONLY: the node-local device path
 *       (e.g. {@code /dev/ttyUSB0}); NULL for tcp/mqtt.</li>
 *   <li>{@code host}/{@code port} — tcp + mqtt ONLY: the radio's / broker's hostname or
 *       IPv4 + TCP port; NULL for serial.</li>
 *   <li>{@code topicRoot}/{@code channelName} — mqtt ONLY: the broker topic root
 *       (e.g. {@code msh/US}) + the Meshtastic channel name the JSON integration
 *       subscribes on; NULL for serial/tcp.</li>
 *   <li>{@code gatewayNodeId} — mqtt ONLY (optional): the mesh gateway node id
 *       ({@code !hex8}) used for downlink attribution; NULL elsewhere.</li>
 *   <li>{@code radioId} — the stable bridge-facing radio identity the meshbridge keys its
 *       channel map on; re-attaching the same radio_id on the same node is idempotent
 *       (at-most-one ACTIVE radio per (device, radio_id)).</li>
 *   <li>{@code meshChannel} — the Meshtastic mesh channel index (0..7) the bridge binds
 *       this radio on.</li>
 *   <li>{@code state} — {@code active} (bridged) / {@code detached} (CAS audit, never
 *       deleted while history matters).</li>
 *   <li>{@code domain} — the residency brand, stamped from the device's residency, never
 *       the caller. A scoped ADMIN reads only own-brand radios.</li>
 *   <li>{@code propagationState} — the on-node meshbridge reconcile ACK the UI surfaces.</li>
 *   <li>{@code generation} — monotonic, bumped on every mutate; the per-node signed export
 *       carries {@code max(generation)} for the node's rollback guard.</li>
 * </ul>
 */
public record RadioDevice(
        String id,
        String deviceId,
        String transport,
        String serialPath,
        String host,
        Integer port,
        String topicRoot,
        String channelName,
        String gatewayNodeId,
        String radioId,
        int meshChannel,
        String state,
        String domain,
        String propagationState,
        long generation,
        String createdBy,
        Instant createdAt,
        Instant detachedAt,
        String detachedBy) {

    public static final String TRANSPORT_SERIAL = "serial";
    public static final String TRANSPORT_TCP = "tcp";
    public static final String TRANSPORT_MQTT = "mqtt";

    public static final String STATE_ACTIVE = "active";
    public static final String STATE_DETACHED = "detached";

    public static final String PROP_PENDING = "pending";
    public static final String PROP_APPLIED = "applied";
    public static final String PROP_FAILED = "failed";
    public static final String PROP_DEGRADED = "degraded";

    public boolean isActive() {
        return STATE_ACTIVE.equals(state);
    }
}
