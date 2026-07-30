/**
 * The DESKTOP-APP-GOVERNANCE BFF leg: the per-license SSO-enforced sudo grants, the admin-curated
 * Discover/Flatpak catalog + user install-requests, the admin REMOTE-INSTALL trigger, and the
 * pre-WS SSH-terminal session descriptor. The live in-UI SSH terminal transport lives in
 * {@link systems.hugmesh.adminbff.desktop.terminal}.
 *
 * <h2>TWO-KEY trust model (by design)</h2>
 * There are TWO distinct key flows; they must not be conflated:
 * <ul>
 *   <li><b>The OPERATOR client key (ssh-issue, #84):</b>
 *       {@link systems.hugmesh.adminbff.sshissue} mints an operator Ed25519 keypair and registers
 *       its fingerprint into a {@code device_ssh_license} row — the credential a PERSON uses to SSH a
 *       node directly. This is NOT the BFF→device credential.</li>
 *   <li><b>The BFF DIAL key (device_ssh_dial, band 170):</b> the BFF authenticates to the device as
 *       {@code device_ssh_dial.dial_user} using its OWN per-device dial PRIVATE key (Vault/ESO-mounted,
 *       in-memory, {@code char[]}-wiped, never logged/persisted/returned). BOTH the in-UI terminal
 *       AND the remote-install ride THIS dial (one host-key-pinned trust path, no second TOFU
 *       surface). Operator accountability for a BFF-driven action lives in the WS/controller audit +
 *       the single-use step-up consume — not in the dial credential.</li>
 * </ul>
 *
 * <h2>Reach control + step-up</h2>
 * Every device-targeting privileged op requires an ACTIVE own-domain device-OR-domain ssh-license for
 * the operator AND rejects {@code device.isSuperadminOwned()} for ADMIN ops (superadmin reach is
 * mesh-membership, never a license), AND requires a fresh step-up token on the SINGLE
 * {@code X-Device-Terminal-StepUp} header (terminal + install share it). Domain is resolved from the
 * cryptographically-validated issuer; operator/owner is {@code jwt.getSubject()} — never a body field.
 * Device-targeting denials collapse to ONE generic 403 (anti-enumeration); the cause stays in a
 * server-side WARN audit.
 *
 * <h2>Ships dark</h2>
 * Every behavior change stays behind an EXISTING default-off flag
 * ({@code app.device-terminal.enabled}, {@code app.desktop.remote-install.enabled},
 * {@code app.device-terminal.dial.enabled}); the authorization is exercised even while dark.
 */
package systems.hugmesh.adminbff.desktop;
