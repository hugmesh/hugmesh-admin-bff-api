package net.hugmesh.adminbff.matrixadmin;

import java.time.Clock;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the ADMIN-only Matrix deactivate (hugmesh-mod-bff-api#23). Its OWN config block
 * ({@code matrix-admin.*}) and its OWN {@link WebClient}, deliberately separate from
 * {@code homeserver.admin.*} / {@code HomeserverAdminConfig}: arming the suspension seam must
 * never arm this one-way verb, and vice versa. The env names are distinct from mod-bff-api's
 * {@code MATRIX_ADMIN_ENABLED} too, so one variable can never arm both services' copies.
 */
@Configuration(proxyBeanMethods = false)
public class MatrixAdminConfig {

    /** Upper bound on the confirmation window; "short-lived" is the point of decision 83a. */
    static final Duration MAX_TTL = Duration.ofMinutes(15);

    @Bean
    MatrixAdminDeactivateClient matrixAdminDeactivateClient(
            WebClient.Builder builder,
            @Value("${matrix-admin.base-url:http://tuwunel.hugmesh-backend.svc.cluster.local:8008}") String baseUrl,
            @Value("${matrix-admin.enabled:false}") boolean enabled,
            // Placeholder only: Vault hugmesh/tuwunel-admin (property "token") via the ESO
            // ExternalSecret 'tuwunel-admin'. Blank => every confirm degrades (no-admin-token).
            @Value("${matrix-admin.admin-token:}") String adminToken,
            @Value("${matrix-admin.server-name:hugmesh.net}") String serverName,
            @Value("${matrix-admin.admin-room:#admins:hugmesh.net}") String adminRoom,
            @Value("${matrix-admin.timeout:PT10S}") Duration timeout) {
        return new MatrixAdminDeactivateClient(builder.clone().baseUrl(baseUrl).build(),
                enabled, adminToken, serverName, adminRoom, timeout);
    }

    @Bean
    MatrixDeactivateService matrixDeactivateService(
            MatrixDeactivateProposalRepository repo,
            MatrixAdminDeactivateClient client,
            @Value("${matrix-admin.deactivate.confirm-ttl:PT2M}") Duration ttl) {
        return new MatrixDeactivateService(repo, client, checkedTtl(ttl), Clock.systemUTC());
    }

    /** Fail the boot on a window that is empty, negative, or not short-lived. */
    static Duration checkedTtl(Duration ttl) {
        if (ttl == null || ttl.isNegative() || ttl.isZero() || ttl.compareTo(MAX_TTL) > 0) {
            throw new IllegalStateException("matrix-admin.deactivate.confirm-ttl must be > 0 and <= "
                    + MAX_TTL + " (got " + ttl + ")");
        }
        return ttl;
    }
}
