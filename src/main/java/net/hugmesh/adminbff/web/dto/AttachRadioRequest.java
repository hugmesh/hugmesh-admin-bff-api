package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/admin/device-radios/{deviceId}/radios} (ADMIN|SUPERADMIN) —
 * attaches a Meshtastic LoRa radio to a mesh node (schema 300). The {@code @NotBlank}/
 * {@code @Pattern}/{@code @Min}/{@code @Max} guards make a MALFORMED FIELD a clean 400
 * BEFORE any write; the CROSS-FIELD per-transport shape matrix (serial → serialPath only;
 * tcp → host+port only; mqtt → host+port+topicRoot+channelName, optional gatewayNodeId —
 * a MIXED shape is rejected) is enforced in
 * {@link net.hugmesh.adminbff.radio.NodeRadioService} (-&gt; 422), the OWNERSHIP
 * ALLOW/DENY gate (the node must be own-domain ADMIN-owned for an ADMIN; SUPERADMIN
 * unrestricted) likewise (DENY -&gt; 403), and the residency-stamped {@code domain} comes
 * from the node, never the caller [FIX-NODEFAULT].
 *
 * <ul>
 *   <li>{@code transport} — {@code serial} (USB-serial device on the node) | {@code tcp}
 *       (LoRa-WiFi radio, Meshtastic TCP API, port defaulted 4403) | {@code mqtt}
 *       (WAN/LoRaWAN-gateway mesh via a Meshtastic MQTT broker, JSON integration).</li>
 *   <li>{@code serialPath} — serial ONLY: the ABSOLUTE node-local {@code /dev/...} path.</li>
 *   <li>{@code host}/{@code port} — tcp + mqtt ONLY: hostname or IPv4 (≤253) + 1..65535.</li>
 *   <li>{@code topicRoot}/{@code channelName} — mqtt ONLY: the broker topic root
 *       (e.g. {@code msh/US}) + the Meshtastic channel name.</li>
 *   <li>{@code gatewayNodeId} — mqtt ONLY (optional): the {@code !hex8} mesh gateway node
 *       id for downlink attribution.</li>
 *   <li>{@code radioId} — the stable bridge-facing radio identity (unique per node while
 *       active); re-attaching the same id on the same node is idempotent.</li>
 *   <li>{@code meshChannel} — the Meshtastic channel index 0..7 the bridge binds.</li>
 * </ul>
 */
public record AttachRadioRequest(
        @NotBlank(message = "transport is required")
        @Pattern(regexp = "serial|tcp|mqtt", message = "transport must be serial, tcp or mqtt")
        String transport,

        @Pattern(regexp = "^/dev/[A-Za-z0-9/._:+-]{1,200}$",
                message = "serialPath must be an absolute /dev/... device path")
        @Nullable
        String serialPath,

        @Size(max = 253, message = "host is too long")
        @Pattern(regexp = "^[A-Za-z0-9]([A-Za-z0-9-]{0,62})?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,62})?)*$",
                message = "host must be a hostname or IPv4 address")
        @Nullable
        String host,

        @Min(value = 1, message = "port must be 1..65535")
        @Max(value = 65535, message = "port must be 1..65535")
        @Nullable
        Integer port,

        @Pattern(regexp = "^[A-Za-z0-9/._-]{1,64}$",
                message = "topicRoot must be a broker topic root (e.g. msh/US)")
        @Nullable
        String topicRoot,

        @Pattern(regexp = "^[A-Za-z0-9._-]{1,32}$",
                message = "channelName must be a Meshtastic channel name")
        @Nullable
        String channelName,

        @Pattern(regexp = "^![0-9a-f]{8}$",
                message = "gatewayNodeId must be a Meshtastic !hex8 node id")
        @Nullable
        String gatewayNodeId,

        @NotBlank(message = "radioId is required")
        @Pattern(regexp = "^[A-Za-z0-9._-]{1,64}$",
                message = "radioId must be 1..64 of [A-Za-z0-9._-]")
        String radioId,

        @Min(value = 0, message = "meshChannel must be 0..7")
        @Max(value = 7, message = "meshChannel must be 0..7")
        int meshChannel) {
}
