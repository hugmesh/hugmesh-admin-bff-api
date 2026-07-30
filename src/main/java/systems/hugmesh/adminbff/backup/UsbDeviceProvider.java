package systems.hugmesh.adminbff.backup;

import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Discovers connected/mountable USB devices on the backup worker node.
 *
 * <p>The DEFAULT implementation here returns an empty list: in a real cluster the
 * USB enumeration runs ON the node (the backup worker DaemonSet/Job reads
 * {@code lsblk -J -o NAME,LABEL,MOUNTPOINT,SIZE,FSAVAIL,RO,TRAN} filtered to
 * {@code TRAN=usb}); the BFF pod itself has no host block-device visibility. The
 * production wiring (a node-agent endpoint the BFF queries, or a short-lived
 * privileged enumerate Job) is documented in {@code jobs/README.md} and is a
 * follow-up. Returning empty (rather than throwing) keeps the {@code GET
 * /bff/admin/usb-devices} contract honest in any environment — the UI shows
 * "no USB devices detected" instead of an error.
 *
 * <p>Made an interface-by-convention (single concrete bean) so a test or a real
 * node-agent-backed implementation can replace it without touching the service.
 */
@Component
public class UsbDeviceProvider {

    /** All currently connected USB devices (empty when none / not wired). */
    public Mono<List<UsbDevice>> list() {
        return Mono.just(List.of());
    }

    /** Look up one device by id; empty Mono when the id is not currently present. */
    public Mono<UsbDevice> find(String id) {
        return list().flatMap(devices -> devices.stream()
                .filter(d -> d.id().equals(id))
                .findFirst()
                .map(Mono::just)
                .orElseGet(Mono::empty));
    }
}
