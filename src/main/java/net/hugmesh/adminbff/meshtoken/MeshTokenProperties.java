package net.hugmesh.adminbff.meshtoken;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import net.hugmesh.commons.security.DomainRegistry;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * {@code app.mesh-token.*} — the web admin UI's HugMesh-token issuer. SHIPS DARK
 * ({@code enabled=false}).
 *
 * <h2>Domains</h2>
 * {@code login-servers} is ONE string, {@code <domain>=<url>[,<domain>=<url>...]}, because it
 * arrives as one env var ({@code APP_MESH_TOKEN_LOGIN_SERVERS}) and a domain's dots would not
 * survive relaxed map binding. Each entry is an access domain this mesh issues tokens for and
 * its headscale URL, which must be {@code https://host[:port]} with the host the domain or a
 * name under it (the token rule; checked at startup when enabled).
 *
 * <p>{@code domain-brands} ({@code <domain>=<brand>,...}) says which tenant brand owns each
 * access domain — the {@code PrincipalDomain} value an ADMIN is walled to. An access domain
 * that is not listed belongs to {@link DomainRegistry#DEFAULT_DOMAIN}, the single-issuer brand,
 * so the local stack needs no second variable.
 */
@Component
@ConfigurationProperties(prefix = "app.mesh-token")
public class MeshTokenProperties {

    /** Master switch. False: POST answers 503 and nothing is minted. */
    private boolean enabled = false;
    /** The mesh id carried in every token ({@code ^[a-z0-9][a-z0-9-]{0,62}$}). */
    private String mesh = "hugmesh-local";
    /** Path of the issuer's Ed25519 private key (OpenSSH or PKCS#8 PEM). Read only when enabled. */
    private String issuerKeyPath = "";
    /** {@code <domain>=<https url>[,...]}. */
    private String loginServers = "";
    /** {@code <domain>=<brand>[,...]}; unlisted domains belong to {@code default}. */
    private String domainBrands = "";
    /** Lifetime when the request names none (7 days). */
    private long defaultLifetimeSeconds = 7L * 24 * 3600;
    /** Longest lifetime this mesh issues; never more than the format's 90 days. */
    private long maxLifetimeSeconds = MeshTokenPayload.MAX_LIFETIME_SECONDS;
    private final Headscale headscale = new Headscale();

    /** The headscale control plane the pre-auth keys are minted on. */
    public static class Headscale {
        private String baseUrl = "http://headscale.hugmesh-pki.svc.cluster.local:8080";
        /** File holding the headscale API key; re-read on every call so rotation needs no restart. */
        private String apiKeyPath = "";
        /** The headscale user (by NAME, headscale 0.23) the keys are created for. */
        private String user = "hugmesh";
        private long timeoutMs = 8000;

        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
        public String getApiKeyPath() { return apiKeyPath; }
        public void setApiKeyPath(String apiKeyPath) { this.apiKeyPath = apiKeyPath; }
        public String getUser() { return user; }
        public void setUser(String user) { this.user = user; }
        public long getTimeoutMs() { return timeoutMs; }
        public void setTimeoutMs(long timeoutMs) { this.timeoutMs = timeoutMs; }
    }

    /** One access domain this mesh issues for. */
    public record DomainEntry(String domain, String loginServer, String brand) {
    }

    /**
     * The parsed, validated domain table, in configuration order. Throws
     * {@link IllegalStateException} naming the bad entry.
     */
    public List<DomainEntry> domains() {
        Map<String, String> brands = parsePairs(domainBrands, "domain-brands");
        List<DomainEntry> out = new ArrayList<>();
        for (Map.Entry<String, String> e : parsePairs(loginServers, "login-servers").entrySet()) {
            String domain = e.getKey().toLowerCase(Locale.ROOT);
            String url = e.getValue();
            while (url.endsWith("/")) {
                url = url.substring(0, url.length() - 1);
            }
            if (!MeshTokenPayload.DOMAIN_RE.matcher(domain).matches()) {
                throw new IllegalStateException("app.mesh-token.login-servers: " + domain
                        + " is not a lower-case domain name with at least two labels.");
            }
            if (!MeshTokenPayload.LOGIN_SERVER_RE.matcher(url).matches() || !MeshTokenPayload.safeAscii(url)) {
                throw new IllegalStateException("app.mesh-token.login-servers: the login server for " + domain
                        + " must be https://host[:port] and nothing else.");
            }
            String host = MeshTokenPayload.loginServerHost(url);
            if (!host.equals(domain) && !host.endsWith("." + domain)) {
                throw new IllegalStateException("app.mesh-token.login-servers: the login server host " + host
                        + " is outside its access domain " + domain + ".");
            }
            String brand = brands.getOrDefault(domain, DomainRegistry.DEFAULT_DOMAIN);
            out.add(new DomainEntry(domain, url, brand));
        }
        return out;
    }

    private static Map<String, String> parsePairs(String raw, String name) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) {
            return out;
        }
        for (String part : raw.split(",")) {
            String p = part.trim();
            if (p.isEmpty()) {
                continue;
            }
            int eq = p.indexOf('=');
            if (eq <= 0 || eq == p.length() - 1) {
                throw new IllegalStateException("app.mesh-token." + name + ": entry '" + p
                        + "' is not <domain>=<value>.");
            }
            String k = p.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            if (out.putIfAbsent(k, p.substring(eq + 1).trim()) != null) {
                throw new IllegalStateException("app.mesh-token." + name + ": " + k + " is listed twice.");
            }
        }
        return out;
    }

    /** The configured cap, clamped to the format's 90 days. */
    public long effectiveMaxLifetimeSeconds() {
        return Math.min(Math.max(maxLifetimeSeconds, 60), MeshTokenPayload.MAX_LIFETIME_SECONDS);
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getMesh() { return mesh; }
    public void setMesh(String mesh) { this.mesh = mesh; }
    public String getIssuerKeyPath() { return issuerKeyPath; }
    public void setIssuerKeyPath(String issuerKeyPath) { this.issuerKeyPath = issuerKeyPath; }
    public String getLoginServers() { return loginServers; }
    public void setLoginServers(String loginServers) { this.loginServers = loginServers; }
    public String getDomainBrands() { return domainBrands; }
    public void setDomainBrands(String domainBrands) { this.domainBrands = domainBrands; }
    public long getDefaultLifetimeSeconds() { return defaultLifetimeSeconds; }
    public void setDefaultLifetimeSeconds(long defaultLifetimeSeconds) { this.defaultLifetimeSeconds = defaultLifetimeSeconds; }
    public long getMaxLifetimeSeconds() { return maxLifetimeSeconds; }
    public void setMaxLifetimeSeconds(long maxLifetimeSeconds) { this.maxLifetimeSeconds = maxLifetimeSeconds; }
    @SuppressFBWarnings(value = "EI_EXPOSE_REP",
            justification = "Spring Boot @ConfigurationProperties nested-bean binding: the field is final with no setter, so the binder must reach the live nested Headscale bean through this getter to populate app.mesh-token.headscale.* ; a copy would silently drop the bound values.")
    public Headscale getHeadscale() { return headscale; }
}
