package net.hugmesh.adminbff.device;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A {@link Device} bundled with the ACTIVE {@link SshLicense}s that directly target it
 * (its DEVICE-scoped licenses) — the shape the admin-ui device-licenses console renders
 * per node. DOMAIN-scoped licenses (which apply to every node resident in a domain) are
 * NOT inlined here; they are surfaced separately so the console can show "this node is
 * also reachable by N domain-wide operators" without duplicating a domain license across
 * every node.
 */
public record DeviceWithLicenses(
        Device device,
        List<SshLicense> deviceLicenses) {

    public DeviceWithLicenses {
        deviceLicenses = deviceLicenses == null ? null : Collections.unmodifiableList(new ArrayList<>(deviceLicenses));
    }
}
