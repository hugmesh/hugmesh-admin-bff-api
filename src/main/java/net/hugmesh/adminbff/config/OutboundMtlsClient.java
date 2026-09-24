package net.hugmesh.adminbff.config;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

/**
 * OUTBOUND (client-side) mTLS for this BFF's calls to first-party in-cluster services
 * (decision 81a = A, hugmesh-admin-bff-api#82 / #94 / #62). Same shape and the same
 * {@code hugmesh.mtls.client.*} properties as hugmesh-mod-bff-api's
 * {@code FederationHttpClientSsl} (and forum-, mesh-, user-bff's copies), so one deployment
 * env ({@code HUGMESH_MTLS_CLIENT_ENABLED}) switches every BFF the same way.
 *
 * <p>When applied, the reactor-netty {@link HttpClient} carries:
 * <ul>
 *   <li>this BFF's PKI CLIENT IDENTITY — the PKCS12 {@code keystore.p12} the pod already
 *       mounts for its own server-side TLS — presented on the handshake, so a callee running
 *       {@code client-auth=need} (federation-api) accepts it; and</li>
 *   <li>the cluster-CA TRUSTSTORE — the PKCS12 {@code truststore.p12} — as the ONLY trust
 *       anchors: a server certificate that does not chain to it (for example ArgoCD's own
 *       self-signed {@code O=Argo CD} leaf) is refused. Decision 81b = B makes ArgoCD's
 *       certificate come from the cluster CA instead (hugmesh-generator), so no ArgoCD
 *       special case lives here, and there is deliberately no plain-http fallback.</li>
 * </ul>
 *
 * <p>It REUSES the same {@code SSL_*} env the server-side stores use ({@code SSL_KEY_STORE},
 * {@code SSL_KEY_STORE_PASSWORD}, {@code SSL_TRUST_STORE}, {@code SSL_TRUST_STORE_PASSWORD},
 * all PKCS12), so one mounted {@code /stores} layout serves both directions.
 *
 * <p>GATED, DEFAULT OFF: {@code hugmesh.mtls.client.enabled=false}. Local/dev/CI is
 * unaffected — the client is left on its default connector (JDK trust, no client
 * certificate). Enabled but with no key-store file present, it logs a warning and also
 * keeps the default connector (the mod-bff behaviour): the https call then fails its
 * handshake loudly rather than the pod crash-looping at boot.
 *
 * <p>ONE MISCONFIGURATION WHERE "ONLY THE CLUSTER CA" DOES NOT HOLD: enabled, key-store
 * present, but no trust-store file. Then (again the mod-bff behaviour) it logs a warning and
 * trusts the JVM DEFAULT anchors instead — never trust-all. The JDK anchors do not include the
 * cluster CA, so every in-cluster callee's handshake is refused in that state, and
 * {@code ArgoCdClientMtlsTest#enabledButTrustStoreAbsent_fallsBackToJvmTrust_notTrustAll} pins
 * that. In-cluster the build-keystore init container always writes both stores.
 */
@ConfigurationProperties(prefix = "hugmesh.mtls.client")
public class OutboundMtlsClient {

    private static final Logger log = LoggerFactory.getLogger(OutboundMtlsClient.class);

    /** Master gate — when false, no SSL is applied and the default connector is kept. */
    private boolean enabled = false;
    /** PKCS12 keystore holding THIS BFF's PKI client identity (cert + key). */
    private String keyStore = "/stores/keystore.p12";
    private String keyStorePassword = "";
    private String keyStoreType = "PKCS12";
    /** PKCS12 truststore holding the cluster CA (the only anchors trusted for the callee). */
    private String trustStore = "/stores/truststore.p12";
    private String trustStorePassword = "";
    private String trustStoreType = "PKCS12";

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getKeyStore() { return keyStore; }
    public void setKeyStore(String keyStore) { this.keyStore = keyStore; }
    public String getKeyStorePassword() { return keyStorePassword; }
    public void setKeyStorePassword(String keyStorePassword) { this.keyStorePassword = keyStorePassword; }
    public String getKeyStoreType() { return keyStoreType; }
    public void setKeyStoreType(String keyStoreType) { this.keyStoreType = keyStoreType; }
    public String getTrustStore() { return trustStore; }
    public void setTrustStore(String trustStore) { this.trustStore = trustStore; }
    public String getTrustStorePassword() { return trustStorePassword; }
    public void setTrustStorePassword(String trustStorePassword) { this.trustStorePassword = trustStorePassword; }
    public String getTrustStoreType() { return trustStoreType; }
    public void setTrustStoreType(String trustStoreType) { this.trustStoreType = trustStoreType; }

    /**
     * Whether outbound client mTLS should be applied: only when the gate is on AND the
     * identity keystore file is present.
     */
    public boolean shouldApply() {
        if (!enabled) return false;
        boolean present = keyStore != null && Files.exists(Path.of(keyStore));
        if (!present) {
            log.warn("[mtls-client] enabled but key-store '{}' is absent — outbound mTLS NOT applied", keyStore);
        }
        return present;
    }

    /**
     * Decorate a reactor-netty {@link HttpClient} with the client-identity keystore and the
     * cluster-CA truststore when {@link #shouldApply()}; otherwise return it unchanged.
     */
    public HttpClient customize(final HttpClient httpClient) {
        if (!shouldApply()) return httpClient;
        try {
            SslContext ssl = buildSslContext();
            log.info("[mtls-client] outbound client-cert presentation ENABLED (key-store={}, trust-store={})",
                    keyStore, trustStore);
            return httpClient.secure(spec -> spec.sslContext(ssl));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build outbound mTLS SslContext from "
                    + keyStore + " / " + trustStore, e);
        }
    }

    /** A fresh {@link HttpClient} with {@link #customize} applied — what the effector clients are built on. */
    public HttpClient httpClient() {
        return customize(HttpClient.create());
    }

    /** Build the client {@link SslContext}: key-manager = client identity, trust-manager = cluster CA. */
    SslContext buildSslContext() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(load(keyStore, keyStoreType, keyStorePassword), pw(keyStorePassword));

        SslContextBuilder builder = SslContextBuilder.forClient().keyManager(kmf);
        // Trust manager (cluster CA) is optional: with no truststore mounted, fall back to the
        // JVM default trust — in-cluster the build-keystore initContainer always writes it.
        if (trustStore != null && Files.exists(Path.of(trustStore))) {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(load(trustStore, trustStoreType, trustStorePassword));
            builder.trustManager(tmf);
        } else {
            log.warn("[mtls-client] trust-store '{}' is absent — falling back to the JVM default trust", trustStore);
        }
        return builder.build();
    }

    private static KeyStore load(String path, String type, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance(type == null ? "PKCS12" : type);
        try (InputStream in = Files.newInputStream(Path.of(path))) {
            ks.load(in, pw(password));
        }
        return ks;
    }

    private static char[] pw(String password) {
        return password == null ? new char[0] : password.toCharArray();
    }
}
