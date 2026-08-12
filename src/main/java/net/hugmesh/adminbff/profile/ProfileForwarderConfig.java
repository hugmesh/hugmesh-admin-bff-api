package net.hugmesh.adminbff.profile;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;

/**
 * Wires the {@link ProfileForwarder} the {@link net.hugmesh.adminbff.AuthController}
 * consumes — the reactive client over the hugmesh-user-bff profile service.
 *
 * <p>Mirrors {@code FederationUsernameConfig} / {@code HomeserverAdminConfig}: the
 * forwarder is ALWAYS present (so the controller injects it non-null) but gated by
 * {@code profile.forward.enabled} (default false) so a user-bff-less dev/test/CI run
 * boots clean. With the gate OFF the forwarder never calls the user-bff and
 * registration is unchanged; the in-cluster deployment flips
 * {@code PROFILE_FORWARD_ENABLED=true} once the user-bff internal profile-upsert is
 * live — config-only, no code change.
 *
 * <p>{@code base-url} defaults to the in-cluster user-bff service. The internal
 * profile-upsert is service-to-service, so an {@code X-Internal-Token} header carries
 * the shared service credential (env-injected; never in git).
 */
@Configuration(proxyBeanMethods = false)
public class ProfileForwarderConfig {

    @Bean
    ProfileForwarder profileForwarder(
            WebClient.Builder builder,
            @Value("${profile.forward.enabled:false}") boolean enabled,
            @Value("${profile.forward.base-url:http://hugmesh-user-bff-api.hugmesh-backend.svc.cluster.local:8080}")
            String baseUrl,
            @Value("${profile.forward.path:/bff/user/profile/internal}") String path,
            @Value("${profile.forward.internal-token-header:X-Internal-Token}") String internalTokenHeader,
            @Value("${profile.forward.internal-token:}") String internalToken,
            ObjectProvider<CasdoorAdminClient> casdoor) {
        // The Casdoor admin client is OPTIONAL (present only when casdoor.admin.enabled=true);
        // getIfAvailable() yields null in a Casdoor-less / unit run so the Casdoor displayName
        // leg is simply skipped.
        return new ProfileForwarder(
                builder.clone().baseUrl(baseUrl).build(),
                enabled, path, internalTokenHeader, internalToken,
                casdoor.getIfAvailable());
    }
}
