package systems.hugmesh.adminbff.device;

/**
 * One row of the PENDING pick-list — a headscale-enrolled node LEFT-JOINed with
 * {@code device_registry}. The SUPERADMIN picks an {@code !registered} node and assigns its
 * owner_type/domain/image_type; the {@link #machineKeyFp()} is the OPAQUE token captured
 * straight from headscale (never typed, never normalised) that the register call carries back
 * and re-validates.
 *
 * @param machineKeyFp the headscale-reported canonical fingerprint (opaque token)
 * @param hostname     the headscale-reported hostname (for human recognition)
 * @param user         the headscale OIDC user the node enrolled under (advisory)
 * @param meshId       the best-effort mesh identifier headscale reports (advisory)
 * @param registered   true iff this fingerprint already exists in device_registry (already
 *                      assigned — shown greyed / non-pickable in the UI)
 * @param domain       the residency already stamped on the registered row (null when pending)
 * @param ownerType    the owner_type already stamped on the registered row (null when pending)
 */
public record PendingNode(
        String machineKeyFp,
        String hostname,
        String user,
        String meshId,
        boolean registered,
        String domain,
        String ownerType) {
}
