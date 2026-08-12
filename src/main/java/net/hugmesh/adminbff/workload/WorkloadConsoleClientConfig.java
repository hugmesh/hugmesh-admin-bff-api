package net.hugmesh.adminbff.workload;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.reactive.handler.SimpleUrlHandlerMapping;
import org.springframework.web.reactive.socket.WebSocketHandler;
import org.springframework.web.reactive.socket.server.support.WebSocketHandlerAdapter;

import java.util.Map;

/**
 * Picks the {@link WorkloadClient} seam, config-only — the SAME pattern as
 * {@code LeaderElectionConfig}:
 *
 * <ul>
 *   <li>{@code app.workload-console.k8s.enabled=true} (in-cluster, RBAC provisioned) →
 *       {@link Fabric8WorkloadClient} over a {@link KubernetesClient} built from the pod's
 *       in-cluster ServiceAccount token. The deployment mounts the read SA's token for the
 *       admin/superadmin reads and the mutate SA's token for the runtime mutations (the
 *       generator provisions both least-privilege SAs);</li>
 *   <li>otherwise (the DEFAULT — cluster-less dev/test/CI, or any deployment that has not
 *       deliberately enabled the k8s seam) → {@link NoopWorkloadClient}, the fail-closed
 *       seam that returns an explicit 503 on every call and never dials the k8s API.</li>
 * </ul>
 *
 * <p>{@link ConditionalOnMissingBean} keeps the Noop as the safety net even if the real bean
 * fails to construct, so the controllers always have a {@link WorkloadClient} to fail-close
 * through. {@link EnableConfigurationProperties} binds the generator-curated allowlists +
 * gate in {@link WorkloadConsoleProperties}.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(WorkloadConsoleProperties.class)
public class WorkloadConsoleClientConfig {

    private static final Logger log = LoggerFactory.getLogger(WorkloadConsoleClientConfig.class);

    @Bean
    @ConditionalOnProperty(name = "app.workload-console.k8s.enabled", havingValue = "true")
    KubernetesClient workloadKubernetesClient() {
        log.info("[workload-console] k8s seam ENABLED — building in-cluster fabric8 client");
        return new KubernetesClientBuilder().build();
    }

    @Bean
    @ConditionalOnProperty(name = "app.workload-console.k8s.enabled", havingValue = "true")
    @ConditionalOnMissingBean(WorkloadClient.class)
    WorkloadClient fabric8WorkloadClient(KubernetesClient client) {
        return new Fabric8WorkloadClient(client);
    }

    @Bean
    @ConditionalOnMissingBean(WorkloadClient.class)
    WorkloadClient noopWorkloadClient() {
        log.info("[workload-console] k8s seam DISABLED — fail-closed NoopWorkloadClient (default)");
        return new NoopWorkloadClient();
    }

    // ── interactive TTY exec WebSocket (DECISION 1, xterm.js) ─────────────────────

    @Bean
    WorkloadExecWebSocketHandler workloadExecWebSocketHandler(WorkloadExecService exec,
                                                              ObjectMapper mapper) {
        return new WorkloadExecWebSocketHandler(exec, mapper);
    }

    /**
     * Maps the exec-TTY handshake at {@code /bff/superadmin/workloads/exec-tty/**} to the WS
     * handler. The handshake (an HTTP GET on the {@code /bff/superadmin/workloads/**} prefix)
     * is gated by BOTH Spring Security's {@code hasRole('SUPERADMIN')} AND the central
     * {@link WorkloadAuthorizationFilter} (DANGEROUS tier: dangerous-tier kill + step-up +
     * device/SSH-license + namespace allowlist), so an unauthorized upgrade is refused before
     * the handler runs. HIGHEST_PRECEDENCE so it wins the path over the annotated controllers.
     */
    @Bean
    SimpleUrlHandlerMapping workloadExecWsHandlerMapping(WorkloadExecWebSocketHandler handler) {
        Map<String, WebSocketHandler> map =
                Map.of("/bff/superadmin/workloads/exec-tty/**", handler);
        SimpleUrlHandlerMapping mapping = new SimpleUrlHandlerMapping();
        mapping.setUrlMap(map);
        mapping.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return mapping;
    }

    @Bean
    WebSocketHandlerAdapter workloadWebSocketHandlerAdapter() {
        return new WebSocketHandlerAdapter();
    }
}
