package net.hugmesh.adminbff.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import reactor.netty.http.client.HttpClient;

import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit pins for {@link OutboundMtlsClient} (decision 81a = A): the gate, the absent-store
 * degrade, and — against the REAL packaged {@code application.yml} — the property/env names the
 * deployment relies on ({@code HUGMESH_MTLS_CLIENT_ENABLED} plus the shared {@code SSL_*}
 * stores). The handshake behaviour itself is proven end to end in
 * {@code FederationModuleClientMtlsTest} and {@code ArgoCdClientMtlsTest}.
 */
class OutboundMtlsClientTest {

    private static final String PW = "changeit";

    @Test
    void disabledByDefault_leavesTheHttpClientUntouched() {
        OutboundMtlsClient mtls = new OutboundMtlsClient();
        assertThat(mtls.isEnabled()).isFalse();
        assertThat(mtls.shouldApply()).isFalse();
        HttpClient base = HttpClient.create();
        assertThat(mtls.customize(base)).isSameAs(base);
    }

    @Test
    void enabledButKeyStoreAbsent_keepsTheDefaultConnector() {
        OutboundMtlsClient mtls = new OutboundMtlsClient();
        mtls.setEnabled(true);
        mtls.setKeyStore("/stores/does-not-exist-" + System.nanoTime() + ".p12");
        assertThat(mtls.shouldApply()).isFalse();
        HttpClient base = HttpClient.create();
        assertThat(mtls.customize(base)).isSameAs(base);
    }

    @Test
    void enabledWithStores_buildsAClientContextAndDecoratesTheHttpClient(@TempDir Path dir) throws Exception {
        TestPki.Issued ca = TestPki.ca("test cluster CA");
        TestPki.Issued id = TestPki.clientLeaf(ca, "hugmesh-admin-bff-api");
        OutboundMtlsClient mtls = enabled(
                TestPki.keyStore(dir, "keystore.p12", PW, id, ca.cert()),
                TestPki.trustStore(dir, "truststore.p12", PW, ca.cert()));

        assertThat(mtls.shouldApply()).isTrue();
        assertThat(mtls.buildSslContext().isClient()).isTrue();
        HttpClient base = HttpClient.create();
        assertThat(mtls.customize(base)).isNotSameAs(base);
    }

    @Test
    void enabledWithAWrongKeyStorePassword_failsLoudlyInsteadOfSilentlyDroppingTls(@TempDir Path dir)
            throws Exception {
        TestPki.Issued ca = TestPki.ca("test cluster CA");
        TestPki.Issued id = TestPki.clientLeaf(ca, "hugmesh-admin-bff-api");
        OutboundMtlsClient mtls = enabled(
                TestPki.keyStore(dir, "keystore.p12", PW, id, ca.cert()),
                TestPki.trustStore(dir, "truststore.p12", PW, ca.cert()));
        mtls.setKeyStorePassword("not-the-password");
        assertThatThrownBy(mtls::httpClient).isInstanceOf(IllegalStateException.class);
    }

    /** The packaged application.yml, with no env set: gate OFF, the /stores defaults. */
    @Test
    void packagedYaml_defaultsToOff_withTheMountedStorePaths() throws Exception {
        OutboundMtlsClient bound = bindFromPackagedYaml(Map.of());
        assertThat(bound.isEnabled()).isFalse();
        assertThat(bound.getKeyStore()).isEqualTo("/stores/keystore.p12");
        assertThat(bound.getTrustStore()).isEqualTo("/stores/truststore.p12");
        assertThat(bound.getKeyStoreType()).isEqualTo("PKCS12");
        assertThat(bound.getTrustStoreType()).isEqualTo("PKCS12");
    }

    /**
     * The env names the deployment sets must reach the binding: HUGMESH_MTLS_CLIENT_ENABLED (the
     * same switch as mod-/forum-/mesh-/user-bff) and the SAME SSL_* the server-side stores use.
     */
    @Test
    void packagedYaml_readsHugmeshMtlsClientEnabledAndTheSharedSslStoreEnv() throws Exception {
        OutboundMtlsClient bound = bindFromPackagedYaml(Map.of(
                "HUGMESH_MTLS_CLIENT_ENABLED", "true",
                "SSL_KEY_STORE", "/k/ks.p12",
                "SSL_KEY_STORE_PASSWORD", "kpw",
                "SSL_KEY_STORE_TYPE", "JKS",
                "SSL_TRUST_STORE", "/k/ts.p12",
                "SSL_TRUST_STORE_PASSWORD", "tpw",
                "SSL_TRUST_STORE_TYPE", "JKS"));
        assertThat(bound.isEnabled()).isTrue();
        assertThat(bound.getKeyStore()).isEqualTo("/k/ks.p12");
        assertThat(bound.getKeyStorePassword()).isEqualTo("kpw");
        assertThat(bound.getKeyStoreType()).isEqualTo("JKS");
        assertThat(bound.getTrustStore()).isEqualTo("/k/ts.p12");
        assertThat(bound.getTrustStorePassword()).isEqualTo("tpw");
        assertThat(bound.getTrustStoreType()).isEqualTo("JKS");
    }

    private static OutboundMtlsClient enabled(Path keyStore, Path trustStore) {
        OutboundMtlsClient mtls = new OutboundMtlsClient();
        mtls.setEnabled(true);
        mtls.setKeyStore(keyStore.toString());
        mtls.setKeyStorePassword(PW);
        mtls.setTrustStore(trustStore.toString());
        mtls.setTrustStorePassword(PW);
        return mtls;
    }

    private static OutboundMtlsClient bindFromPackagedYaml(Map<String, Object> env) throws Exception {
        StandardEnvironment environment = new StandardEnvironment();
        // Drop the real process env/system props so the host running the test cannot leak in.
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().addFirst(new MapPropertySource("fake-env", env));
        for (PropertySource<?> ps : new YamlPropertySourceLoader()
                .load("application.yml", new ClassPathResource("application.yml"))) {
            environment.getPropertySources().addLast(ps);
        }
        return Binder.get(environment).bind("hugmesh.mtls.client", OutboundMtlsClient.class)
                .orElseThrow(() -> new AssertionError("hugmesh.mtls.client is not bound from application.yml"));
    }
}
