package net.hugmesh.adminbff.federation;

import org.junit.jupiter.api.Test;

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
}
