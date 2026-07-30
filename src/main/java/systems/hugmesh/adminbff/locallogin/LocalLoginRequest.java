package systems.hugmesh.adminbff.locallogin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/login/local} — the passwordless local-secrets login
 * (the login-ui role-picker → loopback-agent handoff flow, contract v1). Sibling of
 * {@link systems.hugmesh.authcore.web.dto.LoginRequest}, but carries the
 * agent-vended {@code secret} that {@code AuthController#loginLocal} FULLY validates
 * against Casdoor before any session is minted.
 *
 * <ul>
 *   <li>{@code roleId} — TELEMETRY ONLY. The local agent's card id (e.g.
 *       {@code brandowner}). It is NEVER trusted for authentication or authorization —
 *       the granted roles come from the looked-up account, not this field. Optional,
 *       length-bounded.</li>
 *   <li>{@code username} — the Casdoor identity the agent vended (e.g.
 *       {@code brandowner@acme.local}). REQUIRED: it is both the credential validated
 *       against Casdoor AND the key of the account lookup, so the validated identity and
 *       the loaded account are the same string (no confused deputy).</li>
 *   <li>{@code secret} — the single-use, short-TTL local secret the agent handed off.
 *       REQUIRED. Validated as a real Casdoor credential (resource-owner-password grant);
 *       it is NEVER logged and NEVER persisted here.</li>
 * </ul>
 */
public record LocalLoginRequest(
        @Size(max = 128, message = "roleId is too long")
        String roleId,

        @NotBlank(message = "username is required")
        @Size(max = 320, message = "username is too long")
        String username,

        @NotBlank(message = "secret is required")
        @Size(max = 4096, message = "secret is too long")
        String secret) {
}
