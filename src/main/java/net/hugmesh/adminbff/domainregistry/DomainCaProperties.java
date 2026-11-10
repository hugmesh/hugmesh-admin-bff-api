package net.hugmesh.adminbff.domainregistry;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code app.domain-registry.ca.*} — the per-domain CA effector (hugmesh-admin-bff-api#99,
 * decision 87a = B: the admin-bff creates the per-domain CA in Vault's PKI engine).
 *
 * <p>SHIPS DARK: {@link #enabled} defaults to {@code false}. While it is false no Vault client
 * is wired, no reconcile loop is scheduled, and {@link DomainCaEffector} answers every call
 * with {@code DISABLED} without touching Vault or the database.
 *
 * <p>The Vault token is an operator-injected credential (ESO/Vault-backed secret through
 * {@code APP_DOMAIN_REGISTRY_CA_VAULT_TOKEN}); it defaults EMPTY and nothing here logs it.
 * Enabling the effector without a token or a Vault address fails the context at boot (see
 * {@link DomainCaConfig#requireConfigured}).
 */
@ConfigurationProperties(prefix = "app.domain-registry.ca")
public class DomainCaProperties {

    /** Master gate. Default false: no Vault call, no DB write, no scheduled tick. */
    private boolean enabled = false;

    /** Vault's API base URL (HTTPS, chained to the cluster CA the outbound client trusts). */
    private String vaultAddr = "https://vault.vault.svc.cluster.local:8200";

    /** Vault token sent as {@code X-Vault-Token}. Never committed, never logged. */
    private String vaultToken = "";

    /**
     * Prefix of each domain's PKI mount; the mount is {@code <prefix><slug>} (decision 87b = A:
     * one root per domain, so one mount per domain). The slug is the domain's immutable
     * {@code ns_prefix} (decision 29a), so the mount path never moves under a live domain.
     */
    private String mountPrefix = "pki-domain-";

    /** {@code max_lease_ttl} of a newly mounted per-domain PKI engine. */
    private String maxLeaseTtl = "87600h";

    /** Lifetime of the generated self-signed root. */
    private String rootTtl = "87600h";

    /** Root key family, kept in lockstep with the vault-pki init defaults (rsa | ec). */
    private String keyType = "rsa";

    /** RSA modulus or EC curve size of the root key. */
    private int keyBits = 4096;

    /** Signature digest size of the root certificate (384 = SHA-384). */
    private int signatureBits = 384;

    /** Per-request timeout towards Vault. */
    private long timeoutMs = 15000;

    /** Delay between reconcile passes (only scheduled when enabled). */
    private long reconcileIntervalMs = 60000;

    /** Delay before the first reconcile pass after boot. */
    private long reconcileInitialDelayMs = 45000;

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getVaultAddr() { return vaultAddr; }
    public void setVaultAddr(String vaultAddr) { this.vaultAddr = vaultAddr; }

    public String getVaultToken() { return vaultToken; }
    public void setVaultToken(String vaultToken) { this.vaultToken = vaultToken; }

    public String getMountPrefix() { return mountPrefix; }
    public void setMountPrefix(String mountPrefix) { this.mountPrefix = mountPrefix; }

    public String getMaxLeaseTtl() { return maxLeaseTtl; }
    public void setMaxLeaseTtl(String maxLeaseTtl) { this.maxLeaseTtl = maxLeaseTtl; }

    public String getRootTtl() { return rootTtl; }
    public void setRootTtl(String rootTtl) { this.rootTtl = rootTtl; }

    public String getKeyType() { return keyType; }
    public void setKeyType(String keyType) { this.keyType = keyType; }

    public int getKeyBits() { return keyBits; }
    public void setKeyBits(int keyBits) { this.keyBits = keyBits; }

    public int getSignatureBits() { return signatureBits; }
    public void setSignatureBits(int signatureBits) { this.signatureBits = signatureBits; }

    public long getTimeoutMs() { return timeoutMs; }
    public void setTimeoutMs(long timeoutMs) { this.timeoutMs = timeoutMs; }

    public long getReconcileIntervalMs() { return reconcileIntervalMs; }
    public void setReconcileIntervalMs(long reconcileIntervalMs) { this.reconcileIntervalMs = reconcileIntervalMs; }

    public long getReconcileInitialDelayMs() { return reconcileInitialDelayMs; }
    public void setReconcileInitialDelayMs(long reconcileInitialDelayMs) { this.reconcileInitialDelayMs = reconcileInitialDelayMs; }

    /** Debug-safe rendering: the token is reported only as present/absent. */
    @Override
    public String toString() {
        return "DomainCaProperties{enabled=" + enabled + ", vaultAddr=" + vaultAddr
                + ", vaultToken=" + (vaultToken == null || vaultToken.isBlank() ? "<unset>" : "<set>")
                + ", mountPrefix=" + mountPrefix + "}";
    }
}
