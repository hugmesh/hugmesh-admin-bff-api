package net.hugmesh.adminbff.federation;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit-level pin of {@link SessionExchangeConfig}'s self-call decision logic — no Spring
 * context, no real HTTP client, no Testcontainers Postgres needed (admin-bff-api's full
 * {@code @SpringBootTest} boot tests are heavier; this exercises the LOGIC these {@code
 * @Bean} methods delegate to, directly).
 */
class SessionExchangeConfigTest {

    private static final String DEFAULT_HOST =
            "hugmesh-admin-bff-api.hugmesh-backend.svc.cluster.local";

    @Test
    void defaultsToPlainHttp_onTheAdminBffServiceDnsName_whenSslDisabled_andNoOverride() {
        assertThat(SessionExchangeConfig.computeBaseUrl("", false, 8080))
                .isEqualTo("http://" + DEFAULT_HOST + ":8080");
    }

    @Test
    void defaultsToHttps_onTheAdminBffServiceDnsName_whenSslEnabled_andNoOverride() {
        // Automatically tracks server.ssl.enabled — see class javadoc "mTLS": an
        // in-cluster deployment with mTLS enforced gets a working self-call with ZERO new
        // operator configuration. NOT literal localhost — see class javadoc "Self-call
        // target": this service's TLS cert is signed for the Service DNS name.
        assertThat(SessionExchangeConfig.computeBaseUrl("", true, 8443))
                .isEqualTo("https://" + DEFAULT_HOST + ":8443");
    }

    @Test
    void nullOverride_treatedTheSameAsBlank() {
        assertThat(SessionExchangeConfig.computeBaseUrl(null, false, 8080))
                .isEqualTo("http://" + DEFAULT_HOST + ":8080");
    }

    @Test
    void explicitOverride_alwaysWins_regardlessOfSslFlag() {
        assertThat(SessionExchangeConfig.computeBaseUrl("http://other-host:9999", true, 8443))
                .isEqualTo("http://other-host:9999");
        assertThat(SessionExchangeConfig.computeBaseUrl("https://other-host:9999", false, 8080))
                .isEqualTo("https://other-host:9999");
    }

    @Test
    void buildClientSslContext_failsFast_withAHelpfulMessage_whenKeyStoreUnreadable() {
        assertThatThrownBy(() -> SessionExchangeConfig.buildClientSslContext(
                "/nonexistent/keystore.p12", "PKCS12", "",
                "/nonexistent/truststore.p12", "PKCS12", ""))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("/nonexistent/keystore.p12")
                .hasMessageContaining("app.bff-exchange.enabled=true");
    }

    // ── Decision 60 (operator, 2026-09-18, "extend"): cache-ttl-ms default is 0 ───────────
    //
    // Mirrors hugmesh-gateway#30's own three-statement guard shape for
    // BffJwtExchangeWebFilter — the number has to agree in THREE independent places
    // (the named pin, the @Value fallback, the shipped application.yml default), and a
    // coherent drift of all three back to 5000 (or any positive value) has to go red.

    private static String shippedValue(String key) throws Exception {
        List<PropertySource<?>> sources = new YamlPropertySourceLoader()
                .load("application.yml", new ClassPathResource("application.yml"));
        for (PropertySource<?> ps : sources) {
            Object v = ps.getProperty(key);
            if (v != null) {
                return v.toString();
            }
        }
        return null;
    }

    @Test
    void applicationYml_cacheTtlDefault_is0_cacheOff_notThe5sWindow() throws Exception {
        // The shipped application.yml default is what actually takes effect at runtime
        // (the @Value fallback below is dead the moment application.yml supplies the
        // key). This fails if the YAML default drifts back to 5000 (the pre-Decision-60
        // window) or to any other positive value — each of which silently reopens a
        // suspension-bypass window on this service's mirrored cache.
        String raw = shippedValue("app.bff-exchange.cache-ttl-ms");
        assertThat(raw)
                .as("application.yml must wire bff-exchange cache-ttl-ms as an env placeholder")
                .isNotNull()
                .startsWith("${APP_BFF_EXCHANGE_CACHE_TTL_MS:")
                .endsWith("}");
        String yamlDefault = raw.substring(
                "${APP_BFF_EXCHANGE_CACHE_TTL_MS:".length(), raw.length() - 1);
        assertThat(yamlDefault)
                .as("Decision 60 (operator, 2026-09-18): application.yml must default "
                        + "bff-exchange cache-ttl-ms to 0 (cache OFF) — 5000 reopens a 5 s "
                        + "suspension-bypass window on this service's mirrored cache")
                .isEqualTo("0")
                .isEqualTo(String.valueOf(SessionExchangeConfig.DEFAULT_CACHE_TTL_MS));
    }

    private static Value cacheTtlMsValueAnnotation() throws NoSuchMethodException {
        Method beanMethod = SessionExchangeConfig.class.getDeclaredMethod(
                "sessionExchangeCache", long.class, int.class);
        Parameter ttlParam = beanMethod.getParameters()[0];
        return ttlParam.getAnnotation(Value.class);
    }

    @Test
    void sessionExchangeCacheBean_valueFallback_matchesTheDocumentedConstant_andTheWiredYaml()
            throws Exception {
        // Read the REAL @Value annotation reflectively (not a copy-pasted literal), so a
        // reworded or accidentally-removed annotation cannot satisfy this test.
        Value ttlValue = cacheTtlMsValueAnnotation();
        assertThat(ttlValue)
                .as("sessionExchangeCache's first parameter must stay @Value-annotated")
                .isNotNull();
        assertThat(ttlValue.value())
                .as("Decision 60 (operator, 2026-09-18): the cache-ttl-ms @Value fallback must "
                        + "stay at 0 (cache OFF) — 5000 reopens a 5 s suspension-bypass window, "
                        + "in each case with no YAML change to review")
                .isEqualTo("${app.bff-exchange.cache-ttl-ms:"
                        + SessionExchangeConfig.DEFAULT_CACHE_TTL_MS + "}")
                .isEqualTo("${app.bff-exchange.cache-ttl-ms:0}");

        String yamlDefault = shippedValue("app.bff-exchange.cache-ttl-ms");
        assertThat(yamlDefault).isEqualTo("${APP_BFF_EXCHANGE_CACHE_TTL_MS:"
                + SessionExchangeConfig.DEFAULT_CACHE_TTL_MS + "}");
    }

    @Test
    void shippedDefault_cacheOff_everySessionExchangeCallConsultsTheGate_aDriftBackTo5000GoesRed()
            throws Exception {
        // Behavioural half: build the REAL cache (and a SessionExchangeService around it)
        // from the numeric fallback parsed out of the live @Value annotation — not a
        // hardcoded literal — and prove three exchanges for the SAME bff_ token are three
        // distinct calls to the transport, i.e. no cache hit ever serves a suspension a
        // stale answer. If the fallback drifts to 5000 the FIRST assertion below goes red
        // before this loop even runs; the loop is the backstop for a mutation that keeps
        // the literal 0 but reopens the window some other way (e.g. reading a non-positive
        // TTL as "cache enabled").
        Value ttlValue = cacheTtlMsValueAnnotation();
        String defaultPart = ttlValue.value().substring(
                ttlValue.value().indexOf(':') + 1, ttlValue.value().length() - 1);
        long ttl = Long.parseLong(defaultPart);
        assertThat(ttl).as("the shipped cache-ttl-ms default is 0 — cache OFF").isZero();

        AtomicInteger calls = new AtomicInteger();
        SessionExchangeCache cache = new SessionExchangeCache(ttl, 10);
        assertThat(cache.enabled()).as("cache must be disabled at the shipped default").isFalse();
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> {
                    calls.incrementAndGet();
                    return Mono.just("custody-" + calls.get());
                },
                cache, Duration.ofSeconds(1));

        for (int i = 1; i <= 3; i++) {
            StepVerifier.create(svc.exchange("bff_shipped-default"))
                    .expectNext("custody-" + i)
                    .verifyComplete();
        }
        assertThat(calls.get())
                .as("Decision 60: cache OFF by default => every exchange call re-consults "
                        + "InternalAccountController's suspensionGate() (3 requests, 3 calls); "
                        + "a 5000 default would make this 1")
                .isEqualTo(3);
    }
}
