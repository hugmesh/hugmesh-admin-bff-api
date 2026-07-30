package systems.hugmesh.adminbff.storage;

/**
 * The OWNERSHIP ALLOW/DENY wall's DENY signal — raised by {@link NodeStorageService} when a
 * caller is not permitted to act on a node's storage under the device-ownership gating
 * matrix (the deliberate DIVERGENCE from SSH licensing):
 *
 * <ul>
 *   <li>an ADMIN acting on a node OUTSIDE their own residency domain;</li>
 *   <li>an ADMIN acting on ANY SUPERADMIN-owned node (those are SUPERADMIN-only).</li>
 * </ul>
 *
 * <p>Distinct from {@link IllegalArgumentException} (which the controller maps to a 422 for
 * VALIDATION failures — no-default residency, over-subscription, unknown node): a DENY is a
 * 403 (the caller is authenticated + role-gated at the path, but not entitled to THIS
 * node's storage). The controller maps this to {@code ApiException.forbidden}.
 */
public class StorageAccessDeniedException extends RuntimeException {
    public StorageAccessDeniedException(String message) {
        super(message);
    }
}
