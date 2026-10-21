package net.hugmesh.adminbff.federation;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;

/**
 * Wires the native-login ({@code bff_}) → custody-JWT exchange path {@link
 * BearerForwardingFilter} uses for a native-login caller — calling admin-bff-api's OWN
 * {@code POST /bff/internal/session/exchange} ({@code InternalAccountController}) over
 * HTTP, exactly like a remote caller (the gateway, mod-bff-api) would.
 *
 * <h3>A genuine self-loopback, on purpose</h3>
 * admin-bff-api already HOLDS every bean {@code InternalAccountController#exchange} needs
 * ({@code AccountStore}, {@code BffCustodyCipher}, {@code OidcExchangeClient}, {@code
 * SuspensionService}) in the SAME JVM — an in-process call bypassing HTTP entirely would
 * avoid this network hop. This deliberately does NOT do that: {@link
 * BearerForwardingFilter} is kept BYTE-IDENTICAL between admin-bff-api and mod-bff-api
 * (mod-bff-api has no choice but to cross HTTP — it holds none of those beans), and having
 * admin-bff-api's copy silently take an in-process shortcut would mean the two services'
 * caller-side code, despite looking byte-identical, would ACTUALLY exercise two entirely
 * different code paths with different failure/latency/cache characteristics — precisely
 * the kind of drift the "byte-identical" convention exists to prevent. The cost is a real,
 * avoidable one (an extra loopback network round-trip on the critical path of every
 * federation-api-bound call from a native-login admin, when this feature is opted in) —
 * bounded by the SAME positive-result cache {@link SessionExchangeCache} gives every other
 * caller of this exchange, and paid ONLY when {@code app.bff-exchange.enabled=true}.
 *
 * <h3>GATED OFF BY DEFAULT</h3>
 * {@code app.bff-exchange.enabled=false} (default) ⇒ this whole config is absent ⇒ {@link
 * BearerForwardingFilter} degrades to EXACTLY today's behaviour for a native-login caller
 * (no {@code Authorization} header forwarded) with ZERO extra network calls. This flag is
 * DELIBERATELY separate from (and must be turned on IN ADDITION to) {@code
 * app.bff.custody-key} (and, for the lazy-refresh leg, {@code app.bff.oidc.enabled}) —
 * those gate whether {@code /bff/internal/session/exchange} can serve a real Bearer at
 * all; THIS flag gates whether {@link BearerForwardingFilter} even ATTEMPTS to call it.
 * Turning this flag on alone (without custody configured) is harmless but pointless: every
 * exchange attempt receives a 503 ("custody disabled") and the filter still falls through
 * to no header — just after one extra loopback round trip. Mirrors the SAME two-layer
 * opt-in the gateway's own {@code hugmesh.gateway.bff-exchange.enabled} + admin-bff's
 * custody flags already require.
 *
 * <h3>Self-call target: the SAME in-cluster Service DNS name, NOT literal localhost</h3>
 * The default target is {@code hugmesh-admin-bff-api.hugmesh-backend.svc.cluster.local}
 * — the IDENTICAL DNS name mod-bff-api's own {@code AdminBffSessionAuthConfig} (and the
 * gateway) already use to reach admin-bff-api — deliberately NOT {@code localhost}, even
 * though the call is conceptually "this service calling itself": admin-bff-api's TLS
 * server certificate (Vault-PKI-issued, {@code server.ssl.key-store}) is signed for the
 * Service DNS name, not for {@code localhost}, so a client that verifies the peer
 * hostname (as any correctly-configured TLS client should) would fail the handshake
 * against a {@code localhost} target. Routing through the Service DNS name means the mTLS
 * peer-identity check succeeds exactly the same way it already does for every OTHER
 * caller of this endpoint (the gateway, mod-bff-api) — the request may land on any
 * admin-bff-api replica via the Service's normal load-balancing, which is harmless here
 * (every replica shares the SAME DB-backed {@code AccountStore}/custody data, so the
 * exchange result is identical regardless of which replica answers).
 *
 * <h3>mTLS — mirrors this service's OWN server.ssl.* automatically</h3>
 * The scheme (and whether a client certificate is presented at all) tracks {@code
 * server.ssl.enabled} — this service's OWN TLS posture (see {@code application.yml}'s
 * "API-to-API mTLS enforcement" block) — and the client identity is built from this
 * service's OWN {@code server.ssl.key-store}/{@code trust-store}. Reusing them means an
 * in-cluster deployment that has turned on {@code server.ssl.enabled=true,
 * client-auth=need} gets a WORKING self-call with ZERO new stores/secrets to provision:
 * this service's own cert (signed by the cluster CA) is presented as the CLIENT identity,
 * and its own truststore (the cluster CA) validates the far end — which is ANOTHER
 * instance of the SAME service, signed by the SAME CA, so this trivially succeeds
 * whenever the server-side TLS is healthy. {@code app.bff-exchange.self-base-url} can
 * still override the computed default explicitly (e.g. a non-default Service name, or a
 * literal pod IP/loopback in a topology where hostname verification is handled
 * differently). The outbound credential is the SAME {@code app.internal.token}/{@code
 * app.internal.token-header} this service's own {@code InternalTokenWebFilter}
 * (auth-core) already validates INBOUND requests against — reused here as the OUTBOUND
 * stamp, so there is exactly one internal token secret for this service to provision, not
 * two.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "app.bff-exchange.enabled", havingValue = "true")
public class SessionExchangeConfig {

    private static final Logger log = LoggerFactory.getLogger(SessionExchangeConfig.class);

    @Bean
    WebClient adminBffLoopbackWebClient(
            WebClient.Builder builder,
            @Value("${server.port:8080}") int serverPort,
            @Value("${server.ssl.enabled:false}") boolean sslEnabled,
            @Value("${server.ssl.key-store:/stores/keystore.p12}") String keyStore,
            @Value("${server.ssl.key-store-type:PKCS12}") String keyStoreType,
            @Value("${server.ssl.key-store-password:}") String keyStorePassword,
            @Value("${server.ssl.trust-store:/stores/truststore.p12}") String trustStore,
            @Value("${server.ssl.trust-store-type:PKCS12}") String trustStoreType,
            @Value("${server.ssl.trust-store-password:}") String trustStorePassword,
            @Value("${app.bff-exchange.self-base-url:}") String selfBaseUrlOverride,
            @Value("${app.internal.token-header:X-Internal-Token}") String internalTokenHeader,
            @Value("${app.internal.token:}") String internalToken) throws Exception {
        String baseUrl = computeBaseUrl(selfBaseUrlOverride, sslEnabled, serverPort);

        HttpClient httpClient = HttpClient.create();
        if (sslEnabled) {
            SslContext sslContext = buildClientSslContext(
                    keyStore, keyStoreType, keyStorePassword, trustStore, trustStoreType, trustStorePassword);
            httpClient = httpClient.secure(spec -> spec.sslContext(sslContext));
            log.info("[bff-exchange] self-loopback WebClient -> {} WITH mTLS (server.ssl.enabled=true)", baseUrl);
        } else {
            log.info("[bff-exchange] self-loopback WebClient -> {} WITHOUT mTLS (server.ssl.enabled=false)", baseUrl);
        }

        WebClient.Builder configured = builder
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient));
        if (internalToken != null && !internalToken.isBlank()) {
            String header = (internalTokenHeader == null || internalTokenHeader.isBlank())
                    ? "X-Internal-Token" : internalTokenHeader;
            configured = configured.filter(stampInternalToken(header, internalToken));
        }
        return configured.build();
    }

    /** The SAME in-cluster Service DNS name mod-bff-api's {@code AdminBffSessionAuthConfig}
     *  (and the gateway) already default to for reaching admin-bff-api — see the class
     *  javadoc "Self-call target" section for why this is used instead of {@code localhost}. */
    private static final String DEFAULT_SELF_HOST =
            "hugmesh-admin-bff-api.hugmesh-backend.svc.cluster.local";

    /**
     * Compute the self-call base URL: an explicit {@code app.bff-exchange.self-base-url}
     * override wins outright; otherwise the host is the well-known admin-bff-api Service
     * DNS name (so the peer's TLS certificate — signed for that name, not
     * {@code localhost} — verifies correctly), scheme tracks {@code server.ssl.enabled}
     * (this service's OWN TLS posture), and the port is this service's OWN {@code
     * server.port}. Package-private (not private) so a unit test can pin this decision
     * table without booting a Spring context or an HTTP client.
     */
    static String computeBaseUrl(String override, boolean sslEnabled, int port) {
        if (override != null && !override.isBlank()) {
            return override;
        }
        return (sslEnabled ? "https" : "http") + "://" + DEFAULT_SELF_HOST + ":" + port;
    }

    @Bean
    SessionExchangeClient sessionExchangeClient(WebClient adminBffLoopbackWebClient) {
        return new SessionExchangeClient(adminBffLoopbackWebClient);
    }

    /**
     * Shipped default for {@code app.bff-exchange.cache-ttl-ms}: {@code 0}, i.e. the
     * positive-swap cache is OFF and every exchange call re-consults {@code
     * InternalAccountController}'s {@code suspensionGate()} (zero suspension-bypass
     * window). Set on 2026-09-18 by operator Decision 60 ("extend"): the gateway's own
     * {@code BffJwtExchangeWebFilter} cache already ships at 0 (hugmesh-gateway#30,
     * decision 7 of hugmesh-generator#347); this extends the same zero-window posture to
     * this service's mirrored cache rather than leaving it at the old 5s default, which
     * previously left a front-door-only zero window while federation-api calls from a
     * native-login admin could still ride a swap cached up to 5s earlier.
     *
     * <p>This constant is a PIN, not an operative default: no production code reads it
     * (javadoc and {@code SessionExchangeConfigTest} only) — the number actually takes
     * effect only via the {@code @Value} fallback below and the wired {@code
     * application.yml} default, both held equal to this constant by
     * {@code SessionExchangeConfigTest}, which goes red if either drifts back to
     * {@code 5000} (or to any positive value) on its own.
     */
    static final long DEFAULT_CACHE_TTL_MS = 0L;

    @Bean
    SessionExchangeCache sessionExchangeCache(
            @Value("${app.bff-exchange.cache-ttl-ms:0}") long cacheTtlMillis,
            @Value("${app.bff-exchange.cache-max-size:10000}") int cacheMaxSize) {
        return new SessionExchangeCache(cacheTtlMillis, cacheMaxSize);
    }

    @Bean
    SessionExchangeService sessionExchangeService(
            SessionExchangeClient sessionExchangeClient,
            SessionExchangeCache sessionExchangeCache,
            @Value("${app.bff-exchange.request-timeout-ms:3000}") long requestTimeoutMillis) {
        return new SessionExchangeService(
                sessionExchangeClient, sessionExchangeCache, Duration.ofMillis(requestTimeoutMillis));
    }

    /** Stamp the SAME {@code app.internal.token} this service's own {@code
     *  InternalTokenWebFilter} (auth-core) validates inbound requests against — reused
     *  here as the OUTBOUND credential for this self-loopback call. Blank token (dev/
     *  test/CI default) means "do not stamp", matching {@code InternalTokenWebFilter}'s
     *  own non-enforcing-when-unset posture and mod-bff-api's identical outbound idiom. */
    private static ExchangeFilterFunction stampInternalToken(String header, String token) {
        return ExchangeFilterFunction.ofRequestProcessor(request ->
                Mono.just(ClientRequest.from(request)
                        .headers(h -> h.set(header, token))
                        .build()));
    }

    /** Client identity = THIS service's own cert; trust = THIS service's own truststore
     *  (the cluster CA) — correct for a self-loopback, since the far end IS this service.
     *  Mirrors the gateway's {@code BffJwtExchangeConfig#buildClientSslContext} assembly.
     *  Package-private (not private) so a unit test can exercise the fail-fast
     *  unreadable-store path directly. */
    static SslContext buildClientSslContext(
            String keyStoreLoc, String keyStoreType, String keyStorePassword,
            String trustStoreLoc, String trustStoreType, String trustStorePassword) throws Exception {
        KeyStore ks = load(keyStoreLoc, keyStoreType, keyStorePassword);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, chars(keyStorePassword));

        KeyStore ts = load(trustStoreLoc, trustStoreType, trustStorePassword);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        return SslContextBuilder.forClient().keyManager(kmf).trustManager(tmf).build();
    }

    private static KeyStore load(String location, String type, String password) throws Exception {
        Path path = Path.of(location);
        if (!Files.isReadable(path)) {
            throw new IllegalStateException(
                    "app.bff-exchange.enabled=true + server.ssl.enabled=true but the store is not readable: "
                            + location + " (expected the SAME mounted PKCS12 stores this service's own "
                            + "embedded server uses)");
        }
        KeyStore keyStore = KeyStore.getInstance(type);
        try (InputStream in = Files.newInputStream(path)) {
            keyStore.load(in, chars(password));
        }
        return keyStore;
    }

    private static char[] chars(String s) {
        return s == null ? new char[0] : s.toCharArray();
    }
}
