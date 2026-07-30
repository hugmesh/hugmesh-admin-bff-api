package systems.hugmesh.adminbff.notification;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Read-at-emit-time holder for the {@code @system} sender's per-channel credentials
 * (Notifications PR3 — consumed by the channel adapters in PR5/PR7).
 *
 * <h3>Secrets come from Vault via ESO — NEVER from git</h3>
 * Each channel token is injected from a Spring property
 * ({@code notification.system-account.channel.<channel>.token}) whose VALUE is supplied at
 * runtime by an ExternalSecrets-materialised Kubernetes Secret (mounted as env / a
 * property source), the SAME way {@code casdoor.admin.client-secret} and
 * {@code app.casdoor.systems.client-secret} are sourced. The defaults are EMPTY so a
 * dev/test/CI run with no Vault boots clean and every channel simply reports its token
 * ABSENT (the adapter then degrades / skips — see {@code available(domain)} in PR5/PR7).
 *
 * <p>This bean only ever returns whether a token is PRESENT and (to the adapter) the
 * token value; it never logs the value. Reading at emit-time (rather than caching a
 * snapshot at construction) is deliberate so an ESO rotation that re-renders the
 * property source is picked up without a restart where the property source supports it.
 */
@Component
public class SystemChannelTokens {

    private final String matrix;
    private final String email;
    private final String akkoma;
    private final String forum;

    public SystemChannelTokens(
            @Value("${notification.system-account.channel.matrix.token:}") String matrix,
            @Value("${notification.system-account.channel.email.token:}") String email,
            @Value("${notification.system-account.channel.akkoma.token:}") String akkoma,
            @Value("${notification.system-account.channel.forum.token:}") String forum) {
        this.matrix = matrix;
        this.email = email;
        this.akkoma = akkoma;
        this.forum = forum;
    }

    /** The {@code @system} Matrix access token, or empty when absent (Vault not wired). */
    public Optional<String> matrix() {
        return present(matrix);
    }

    /** The {@code @system} email/SMTP credential, or empty when absent. */
    public Optional<String> email() {
        return present(email);
    }

    /** The {@code @system} akkoma (Mastodon-API) token, or empty when absent. */
    public Optional<String> akkoma() {
        return present(akkoma);
    }

    /** The {@code @system} phpBB forum token, or empty when absent. */
    public Optional<String> forum() {
        return present(forum);
    }

    /** True iff a non-blank token is configured for the named channel — the presence check
     *  the adapter's {@code available(domain)} consults (never logs the value). */
    public boolean hasToken(String channel) {
        return switch (channel == null ? "" : channel.toLowerCase()) {
            case "matrix" -> matrix().isPresent();
            case "email" -> email().isPresent();
            case "akkoma", "mastodon" -> akkoma().isPresent();
            case "forum" -> forum().isPresent();
            default -> false;
        };
    }

    private static Optional<String> present(String v) {
        return (v == null || v.isBlank()) ? Optional.empty() : Optional.of(v);
    }
}
