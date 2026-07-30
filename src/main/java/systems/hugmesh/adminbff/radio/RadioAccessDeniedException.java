package systems.hugmesh.adminbff.radio;

/**
 * The OWNERSHIP ALLOW/DENY wall's DENY signal — raised by {@link NodeRadioService} when a
 * caller is not permitted to act on a node's radios under the device-ownership gating
 * matrix (the same ADMIN-CAPABLE divergence node-storage carries):
 *
 * <ul>
 *   <li>an ADMIN acting on a node OUTSIDE their own residency domain;</li>
 *   <li>an ADMIN acting on ANY SUPERADMIN-owned node (those are SUPERADMIN-only).</li>
 * </ul>
 *
 * <p>Distinct from {@link IllegalArgumentException} (which the controller maps to a 422 for
 * VALIDATION failures — unknown node, a mixed per-transport shape): a DENY is a 403 (the
 * caller is authenticated + role-gated at the path, but not entitled to THIS node's
 * radios). The controller maps this to {@code ApiException.forbidden}.
 */
public class RadioAccessDeniedException extends RuntimeException {
    public RadioAccessDeniedException(String message) {
        super(message);
    }
}
