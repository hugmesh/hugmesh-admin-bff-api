package net.hugmesh.adminbff.workload;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import io.fabric8.kubernetes.client.OAuthTokenProvider;
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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Picks the {@link WorkloadClient} seam, config-only — the SAME pattern as
 * {@code LeaderElectionConfig}:
 *
 * <ul>
 *   <li>{@code app.workload-console.k8s.enabled=true} (in-cluster, RBAC provisioned) →
 *       {@link Fabric8WorkloadClient} over TWO {@link KubernetesClient}s, one per
 *       least-privilege ServiceAccount the generator provisions (workload-console-rbac):
 *       the READ client authenticates with the projected workload-console-read SA token
 *       ({@code app.workload-console.k8s.read-token-file}) and carries every read; the
 *       MUTATE client authenticates with the projected workload-console-mutate SA token
 *       ({@code app.workload-console.k8s.mutate-token-file}) and carries
 *       delete/rollout-restart/exec/port-forward;</li>
 *   <li>otherwise (the DEFAULT — cluster-less dev/test/CI, or any deployment that has not
 *       deliberately enabled the k8s seam) → {@link NoopWorkloadClient}, the fail-closed
 *       seam that returns an explicit 503 on every call and never dials the k8s API.</li>
 * </ul>
 *
 * <h3>NEVER the pod's own SA</h3>
 * The pod runs as backups-effector — its auto-mounted token must never authenticate a console
 * call. Each half's {@link Config} is built FROM {@link Config#empty()}, never by copying the
 * autoconfigured base: the fabric8 copy-constructor re-runs autoConfigure (re-reading the pod
 * SA token) whenever the base was autoconfigured, and null-valued builder setters never
 * override, so a copied config cannot be stripped of the pod identity. From empty, only the
 * cluster coordinates (master URL, CA, namespace) are carried over and the projected token
 * file — via the {@link OAuthTokenProvider} — is the SOLE credential. An ABSENT/unreadable/
 * EMPTY token file degrades THAT HALF to the same 503 posture as the Noop (both absent → the
 * Noop itself). There is no code path from a missing token to the pod SA.
 *
 * <h3>Token rotation</h3>
 * Projected SA tokens are short-lived and rotated on disk by the kubelet, so each half
 * authenticates via a fabric8 {@link OAuthTokenProvider} that re-reads its file — the
 * provider is consulted per request (it takes precedence over the static token fields in
 * fabric8's {@code TokenRefreshInterceptor}), so a rotated token is picked up without a
 * restart. A token file that VANISHES mid-flight raises the 503 unavailable posture from
 * inside the request pipeline, never a fallback.
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
    @ConditionalOnMissingBean(WorkloadClient.class)
    WorkloadClient fabric8WorkloadClient(WorkloadConsoleProperties props) {
        log.info("[workload-console] k8s seam ENABLED — building dual-SA fabric8 clients");
        return buildDualSaClient(props.getK8s(),
                () -> Config.autoConfigure(null),
                cfg -> new KubernetesClientBuilder().withConfig(cfg).build());
    }

    @Bean
    @ConditionalOnMissingBean(WorkloadClient.class)
    WorkloadClient noopWorkloadClient() {
        log.info("[workload-console] k8s seam DISABLED — fail-closed NoopWorkloadClient (default)");
        return new NoopWorkloadClient();
    }

    /**
     * Build the dual-SA client from the two projected token files. Package-private seam so
     * the wiring/no-fallback tests can inject a canned base {@link Config} + client factory:
     * both tokens absent → the {@link NoopWorkloadClient} (dark-by-default preserved, no
     * client is ever built from the pod SA); one absent → a {@link Fabric8WorkloadClient}
     * whose dark half 503s.
     */
    static WorkloadClient buildDualSaClient(WorkloadConsoleProperties.K8s k8s,
                                            Supplier<Config> baseConfigSupplier,
                                            Function<Config, KubernetesClient> clientFactory) {
        Config base = baseConfigSupplier.get();
        KubernetesClient read = saClient("read", k8s.getReadTokenFile(), base, clientFactory);
        KubernetesClient mutate = saClient("mutate", k8s.getMutateTokenFile(), base, clientFactory);
        if (read == null && mutate == null) {
            log.warn("[workload-console] NEITHER SA token file is readable — the console stays "
                    + "fail-closed (NoopWorkloadClient); the pod SA is NEVER used");
            return new NoopWorkloadClient();
        }
        return new Fabric8WorkloadClient(read, mutate);
    }

    /** One per-SA client, or null (→ that half 503s) when its token file is not readable. */
    private static KubernetesClient saClient(String half, String tokenFile, Config base,
                                             Function<Config, KubernetesClient> clientFactory) {
        if (tokenFile == null || tokenFile.isBlank() || !Files.isReadable(Path.of(tokenFile))) {
            log.warn("[workload-console] {} SA token file NOT readable at '{}' — the {} half "
                    + "stays fail-closed (503); NEVER falling back to the pod SA",
                    half, tokenFile, half);
            return null;
        }
        // Per-SA config, built FROM EMPTY — never a copy of the autoconfigured base: the
        // fabric8 Config copy-constructor re-runs autoConfigure (re-reading the pod SA token
        // into autoOAuthToken) whenever the base was autoconfigured, and null-valued builder
        // setters never override, so a copied config cannot be stripped of the pod identity.
        // Only the cluster coordinates are carried over; the projected token provider is the
        // SOLE credential.
        Config cfg = new ConfigBuilder(Config.empty())
                .withMasterUrl(base.getMasterUrl())
                .withCaCertFile(base.getCaCertFile())
                .withCaCertData(base.getCaCertData())
                .withNamespace(base.getNamespace())
                .withOauthTokenProvider(new SaTokenFileProvider(half, Path.of(tokenFile)))
                .build();
        log.info("[workload-console] {} half LIVE — SA token projected at {}", half, tokenFile);
        return clientFactory.apply(cfg);
    }

    /**
     * The rotation-aware credential of one half: re-reads the projected SA token file on
     * every fabric8 request (fabric8 consults the provider per request, ahead of any static
     * token), so kubelet-rotated tokens are picked up without a restart. A file that has
     * VANISHED raises the fail-closed 503 unavailable posture — never a pod-SA fallback.
     */
    static final class SaTokenFileProvider implements OAuthTokenProvider {

        private final String half;
        private final Path path;

        SaTokenFileProvider(String half, Path path) {
            this.half = half;
            this.path = path;
        }

        @Override
        public String getToken() {
            final String token;
            try {
                token = Files.readString(path, StandardCharsets.UTF_8).trim();
            } catch (IOException e) {
                throw WorkloadClientException.unavailable("workload console " + half
                        + " SA token unreadable at " + path
                        + " — fail-closed (no pod-SA fallback)");
            }
            if (token.isEmpty()) {
                // An empty projected file is an unpopulated Secret: 503 fail-closed beats an
                // unattributable 401 (fabric8 sends NO auth header for a blank token).
                throw WorkloadClientException.unavailable("workload console " + half
                        + " SA token EMPTY at " + path + " — fail-closed (no pod-SA fallback)");
            }
            return token;
        }
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
