package systems.hugmesh.adminbff.sshterminal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.desktop.terminal.DeviceTerminalDialProperties;
import systems.hugmesh.commons.security.PrincipalDomain;

/**
 * The SUPERADMIN device-dial LIFECYCLE service — closes the verified {@code canDial()} dead-end.
 * {@code ImageBuildService.seedDial} inserts {@code STATUS_PENDING} rows and
 * {@code SshjDeviceSshChannelFactory} refuses unless an {@code ACTIVE} row exists, but nothing flips
 * PENDING→ACTIVE at runtime — so {@code canDial()} was permanently dead even with both flags on.
 * This service is the deliberate SUPERADMIN control that activates / revokes a dial row.
 *
 * <h3>Why SUPERADMIN-only</h3>
 * Activating a BFF dial key onto a device is a MESH-TRUST operation on the device's pinned host key
 * (the BFF will dial-and-exec as the dial user), NOT a per-domain license — so it sits on the
 * {@code /bff/superadmin/**} gate. The SUPERADMIN-owned-node guard is deliberately NOT applied here
 * (dials legitimately target ANY device, including the BFF's own dial path); instead activation
 * REFUSES a row with no pinned {@code host_key_fp} (a 422 from the controller), the buildable-now
 * safe default. The verifying pinned test-connect is HELD-UNTIL-LIVE behind
 * {@code app.device-terminal.dial.enabled} (it needs a real device).
 *
 * <h3>Lifecycle (CAS + generation, never delete)</h3>
 * {@link #activate} is a compare-and-swap PENDING→ACTIVE at {@code generation+1}; {@link #revoke} is
 * a CAS ACTIVE→REVOKED at {@code generation+1}. Both never delete (the row is the audit trail). A
 * double-activate / double-revoke is an idempotent no-op (0 rows updated, mapped to a no-op result).
 *
 * <h3>Ships dark</h3>
 * No new flag. {@link #activate} is REFUSED while {@code app.device-terminal.dial.enabled=false}
 * (the default) via {@link DialDarkException} (the controller maps it to 503): PENDING rows can be
 * seeded at build time but never activated until launch (and even activated, dialing requires the
 * flag + the sshj factory). Revoke is allowed while dark (a safety/kill action).
 */
@Service
public class DesktopDialService {

    private static final Logger log = LoggerFactory.getLogger(DesktopDialService.class);

    private final DeviceSshDialRepository dials;
    private final DeviceTerminalDialProperties dialProps;

    public DesktopDialService(DeviceSshDialRepository dials, DeviceTerminalDialProperties dialProps) {
        this.dials = dials;
        this.dialProps = dialProps;
    }

    /** Whether the real dial leg is enabled (surfaced for the UI capability probe + ships-dark). */
    public boolean dialEnabled() {
        return dialProps.isEnabled();
    }

    /** The dial rows visible to the caller's scope (SUPERADMIN: all; scoped: own-brand only). */
    public Flux<DeviceSshDial> list(PrincipalDomain scope) {
        return dials.list(scope);
    }

    /** One dial row by device id (non-secret fields), or empty. */
    public Mono<DeviceSshDial> findByDevice(String deviceId) {
        return dials.findByDeviceId(deviceId);
    }

    /**
     * Activate the (seeded, PENDING) dial row for {@code deviceId}: PENDING→ACTIVE at the next
     * generation. Fails {@link DialDarkException} while the dial leg ships dark;
     * {@link DialNotFoundException} if there is no row; {@link DialUnpinnedException} if the row has
     * no pinned {@code host_key_fp} (refuse activation of an unpinned dial — 422). Idempotent: a row
     * already ACTIVE returns a no-op (no error), so a double-activate is safe.
     *
     * <p>HELD-UNTIL-LIVE: a verifying pinned test-connect BEFORE the flip is deferred behind the
     * dial flag + a real device; the buildable-now path is the explicit activate with the
     * refuse-if-unpinned precondition.
     */
    public Mono<DeviceSshDial> activate(String deviceId, String by) {
        if (!dialProps.isEnabled()) {
            return Mono.error(new DialDarkException(
                    "dial activation ships dark (app.device-terminal.dial.enabled=false) — "
                    + "PENDING rows can be seeded but not activated until launch"));
        }
        return dials.findByDeviceId(deviceId)
                .switchIfEmpty(Mono.error(new DialNotFoundException(
                        "no device_ssh_dial row for device=" + deviceId)))
                // Validate host-key pin then CAS to ACTIVE; idempotent if already active.
                .flatMap(row -> activateDialRow(row, deviceId, by));
    }

    /**
     * Revoke the ACTIVE dial row for {@code deviceId}: CAS ACTIVE→REVOKED at the next generation
     * (never deletes). Allowed even while the dial leg is dark (a kill/safety action).
     * {@link DialNotFoundException} if there is no row; idempotent if already non-active.
     */
    public Mono<DeviceSshDial> revoke(String deviceId, String by) {
        return dials.findByDeviceId(deviceId)
                .switchIfEmpty(Mono.error(new DialNotFoundException(
                        "no device_ssh_dial row for device=" + deviceId)))
                // CAS ACTIVE→REVOKED at the next generation; idempotent if already non-active.
                .flatMap(row -> revokeDialRow(row, deviceId, by));
    }

    /** Guard the host-key pin, then CAS to ACTIVE; return existing row if already active. */
    private Mono<DeviceSshDial> activateDialRow(DeviceSshDial row, String deviceId, String by) {
        if (DeviceSshDial.STATUS_ACTIVE.equals(row.status())) {
            log.info("[desktop-dial] activate no-op (already ACTIVE) device={} by={}", deviceId, by);
            return Mono.just(row); // idempotent
        }
        if (row.hostKeyFp() == null || row.hostKeyFp().isBlank()) {
            return Mono.error(new DialUnpinnedException(
                    "refusing to activate device=" + deviceId
                    + " — dial row has no pinned host_key_fp (no TOFU)"));
        }
        long nextGen = row.generation() + 1;
        return dials.activate(row.id(), nextGen).flatMap(updated -> {
            if (updated == 0L) {
                // Lost the CAS (concurrent activate) — re-read the final state.
                return dials.findByDeviceId(deviceId);
            }
            log.info("[desktop-dial] ACTIVATED device={} gen={} by={}", deviceId, nextGen, by);
            return dials.findByDeviceId(deviceId);
        });
    }

    /** CAS ACTIVE→REVOKED at the next generation; return the existing row if already non-active. */
    private Mono<DeviceSshDial> revokeDialRow(DeviceSshDial row, String deviceId, String by) {
        if (!DeviceSshDial.STATUS_ACTIVE.equals(row.status())) {
            log.info("[desktop-dial] revoke no-op (status={}) device={} by={}", row.status(), deviceId, by);
            return Mono.just(row); // idempotent
        }
        long nextGen = row.generation() + 1;
        return dials.revoke(row.id(), nextGen).flatMap(updated -> {
            log.info("[desktop-dial] REVOKED device={} gen={} rows={} by={}", deviceId, nextGen, updated, by);
            return dials.findByDeviceId(deviceId);
        });
    }

    /** No dial row for the target device (controller -> 404/refuse, generic). */
    public static class DialNotFoundException extends RuntimeException {
        public DialNotFoundException(String message) {
            super(message);
        }
    }

    /** Refuse to activate a dial row with no pinned host_key_fp (controller -> 422). */
    public static class DialUnpinnedException extends RuntimeException {
        public DialUnpinnedException(String message) {
            super(message);
        }
    }

    /** Dial activation attempted while the dial leg ships dark (controller -> 503). */
    public static class DialDarkException extends RuntimeException {
        public DialDarkException(String message) {
            super(message);
        }
    }
}
