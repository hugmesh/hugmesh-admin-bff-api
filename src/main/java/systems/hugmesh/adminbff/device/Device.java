package systems.hugmesh.adminbff.device;

import java.time.Instant;

/**
 * A single {@code device_registry} row — the identity + physical ownership + DOMAIN
 * RESIDENCY of one headscale-enrolled mesh node (schema in Liquibase
 * {@code db/changelog/011-device-license-registry.xml}). This is the node a person
 * can/can't SSH into; the registry is the SINGLE SOURCE OF TRUTH the two enforcement
 * layers (per-node sshd {@code AuthorizedKeysCommand} + headscale policy) compile from.
 *
 * <ul>
 *   <li>{@code machineKeyFp} — the stable headscale machine-key fingerprint; the node's
 *       identity (UNIQUE). NOT a node self-claim of residency — residency is the
 *       issuer-keyed {@code domain} stamped by an operator.</li>
 *   <li>{@code imageType} — {@code primary} / {@code mesh-extension} / {@code client}
 *       (CHECK-constrained).</li>
 *   <li>{@code ownerType} — {@code SUPERADMIN} (primary/core node) or {@code ADMIN}
 *       (mesh-extension). The auth predicate DENIES an ADMIN ALL access to a
 *       {@code SUPERADMIN}-owned node, license or not.</li>
 *   <li>{@code physicalOwner} — the Casdoor subject who physically owns/operates the
 *       device.</li>
 *   <li>{@code domain} — the brand/tenant the device is RESIDENT in. NOT NULL with NO
 *       default [FIX-NODEFAULT]; the service rejects {@code 'default'} outright. A
 *       scoped ADMIN only ever reads/operates nodes in their own brand.</li>
 *   <li>{@code meshId} — the headscale mesh the node is enrolled in; SUPERADMIN reach is
 *       gated on the operator's node being in the SAME mesh (mesh-membership is a
 *       precondition, distinct from residency).</li>
 * </ul>
 */
public record Device(
        String id,
        String machineKeyFp,
        String hostname,
        String tailnetId,
        String imageType,
        String hardwareClass,
        String ownerType,
        String physicalOwner,
        String domain,
        String meshId,
        Instant createdAt,
        Instant lastSeenAt) {

    public static final String IMAGE_PRIMARY = "primary";
    public static final String IMAGE_MESH_EXTENSION = "mesh-extension";
    public static final String IMAGE_CLIENT = "client";

    public static final String OWNER_SUPERADMIN = "SUPERADMIN";
    public static final String OWNER_ADMIN = "ADMIN";

    /** True iff this node is SUPERADMIN-owned (core/primary) — the auth predicate denies
     *  every ADMIN, regardless of any license. */
    public boolean isSuperadminOwned() {
        return OWNER_SUPERADMIN.equals(ownerType);
    }
}
