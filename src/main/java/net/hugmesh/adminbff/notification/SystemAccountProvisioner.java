package net.hugmesh.adminbff.notification;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.reserved.ReservedNames;
import net.hugmesh.commons.security.RoleName;

import java.util.List;

/**
 * Provisions the per-domain <b>{@code @system}</b> infra account — the NEUTRAL SENDER
 * for every platform notification (account-status / infra / feature events). It exists
 * so notifications come from a faceless system identity rather than a personal
 * mod/admin account, keeping moderators un-exposed (Notifications PR3). The downstream
 * channel adapters (Matrix DM in PR5, Akkoma local feed in PR7) acquire their access
 * tokens FOR this account; PR3 creates the ACCOUNT + roles + name reservation ONLY — it
 * deliberately mints NO channel tokens.
 *
 * <h3>Reuse — {@link CasdoorAdminClient#ensureUser}</h3>
 * Provisioning delegates to the already-verified {@code ensureUser} primitive
 * (get-user → add-user, idempotent; enables an existing user; ensures each role's
 * membership). We do NOT reimplement any Casdoor call here.
 *
 * <h3>LEAST PRIVILEGE — the load-bearing security property</h3>
 * The {@code @system} account is granted EXACTLY {@link #SYSTEM_ROLES}
 * ({@code [user, matrix, mastodon]}) so a compromised {@code @system} token can post
 * notifications over Matrix/Mastodon and nothing more. It is NEVER granted
 * {@code admin} / {@code superadmin} / {@code mod} — see {@link #SYSTEM_ROLES} and the
 * unit test asserting the exact role list. A regression that widens this set is the key
 * risk this class guards against.
 *
 * <h3>SHIPS DARK</h3>
 * Inert by default: {@code ensureUser} is only reachable when the
 * {@link CasdoorAdminClient} bean exists, and that bean is gated behind
 * {@code casdoor.admin.enabled} (default {@code false}). With the gate off the injected
 * client is {@code null} and {@link #provision(String)} short-circuits to a no-op
 * {@link Mono#empty()} — no Casdoor call, context boots clean.
 *
 * <h3>Per-domain + idempotent</h3>
 * The handle is always {@value #SYSTEM_HANDLE}; the per-domain identity comes from the
 * {@code provider} (the domain's Casdoor org / homeserver) and the derived
 * {@code system@<domain>} email, so provisioning domain {@code X} never touches domain
 * {@code Y}. {@code ensureUser} is get-then-add, so calling {@link #provision(String)}
 * twice is a no-op (no duplicate user, no error).
 */
@Service
public class SystemAccountProvisioner {

    private static final Logger log = LoggerFactory.getLogger(SystemAccountProvisioner.class);

    /**
     * The neutral sender's reserved handle. Held identical to the {@code 'system'} label
     * reserved in {@link ReservedNames#RESERVED} so a regular user can NEVER register a
     * username that would let them spoof the notification sender.
     */
    public static final String SYSTEM_HANDLE = "system";

    /**
     * The EXACT least-privilege role set for the {@code @system} account. The lowercase
     * tokens map to Casdoor roles {@code ROLE_USER}, {@code ROLE_MATRIX},
     * {@code ROLE_MASTODON} (see {@link CasdoorAdminClient#ensureUser}). This list is
     * {@code List.of(...)} — immutable — and is asserted verbatim by the provisioner
     * test: it must NEVER contain {@code admin}, {@code superadmin}, or {@code mod}.
     */
    // The base role token ({@code user}) is sourced from the closed {@link RoleName}
    // enum; {@code matrix}/{@code mastodon} are SERVICE roles (an open set), so they
    // stay free-form String. The serialized values are byte-identical to the prior
    // literals — the assertions and Casdoor wire are unchanged.
    public static final List<String> SYSTEM_ROLES = List.of(RoleName.USER.value(), "matrix", "mastodon");

    /** Roles the {@code @system} account must NEVER hold (defence: an explicit deny-list
     *  used by the unit assertion + the runtime guard below). All three are CLOSED base
     *  role names, sourced from {@link RoleName} (values byte-identical to the prior
     *  {@code "admin"}/{@code "superadmin"}/{@code "mod"} literals). */
    public static final List<String> FORBIDDEN_ROLES =
            List.of(RoleName.ADMIN.value(), RoleName.SUPERADMIN.value(), RoleName.MOD.value());

    /** The real Casdoor admin write client; {@code null} unless
     *  {@code casdoor.admin.enabled=true} — the SHIPS-DARK gate. */
    @Nullable
    private final CasdoorAdminClient casdoor;

    public SystemAccountProvisioner(@Nullable CasdoorAdminClient casdoor) {
        this.casdoor = casdoor;
        // Fail-fast in the (impossible) event the constant is ever edited to include a
        // privileged role — a compile-passing typo must not silently ship an admin
        // @system account.
        for (String r : SYSTEM_ROLES) {
            if (FORBIDDEN_ROLES.contains(r)) {
                throw new IllegalStateException(
                        "SYSTEM_ROLES must never contain a privileged role: " + r);
            }
        }
    }

    /** True when the provisioner can actually write (the SHIPS-DARK gate is open). */
    public boolean enabled() {
        return casdoor != null;
    }

    /**
     * Provision (or idempotently re-provision) the {@code @system} account for
     * {@code domain}. Delegates to {@link CasdoorAdminClient#ensureUser} with the neutral
     * {@value #SYSTEM_HANDLE} handle and EXACTLY {@link #SYSTEM_ROLES}. A no-op
     * {@link Mono#empty()} when the SHIPS-DARK gate is closed ({@code casdoor == null}).
     *
     * @param domain the cluster/brand domain (e.g. {@code acme.test}); used to derive the
     *               {@code system@<domain>} email and as the Casdoor {@code provider}
     *               (the per-domain identity discriminator).
     */
    public Mono<Void> provision(String domain) {
        if (casdoor == null) {
            // SHIPS DARK: no Casdoor write client wired (casdoor.admin.enabled=false).
            log.debug("[system-account] casdoor admin disabled; skipping @system provision for '{}'", domain);
            return Mono.empty();
        }
        String d = domain == null ? "" : domain.trim();
        if (d.isEmpty()) {
            return Mono.error(new IllegalArgumentException("domain is required to provision @system"));
        }
        String email = systemEmail(d);
        // The neutral sender is the SAME handle in every domain; the per-domain identity
        // is carried by the provider + the system@<domain> email. ensureUser is
        // idempotent (get-then-add), so re-provisioning is a safe no-op.
        return casdoor.ensureUser(d, SYSTEM_HANDLE, email, SYSTEM_ROLES)
                .doOnSuccess(v -> log.info(
                        "[system-account] ensured @system for domain '{}' with roles {} (least-privilege; never admin/superadmin/mod)",
                        d, SYSTEM_ROLES));
    }

    /** The {@code system@<domain>} address used as the account email. Not a secret. */
    public static String systemEmail(String domain) {
        return SYSTEM_HANDLE + "@" + (domain == null ? "" : domain.trim());
    }
}
