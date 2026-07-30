package systems.hugmesh.adminbff.device;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the LAYER-A headscale ACL PUSH client + reconcile loop — the leg that
 * COMPILES the signed device-license export into a headscale ACL policy and PUSHES it into
 * headscale via its policy API ({@code PUT /api/v1/policy}). This is the WRITE counterpart to
 * the READ-ONLY {@link HeadscaleNodesClient}: that one reads {@code headscale nodes list};
 * this one writes the mesh's authorized-SSH edges as a headscale policy.
 *
 * <h3>⚠ SHIPS DARK / OFF BY DEFAULT (Layer-B is the load-bearing boundary)</h3>
 * {@link #isEnabled() enabled} defaults <b>false</b>: with no headscale control node and no
 * configured API key (CI, dev, every existing test, a fresh single-stick deployment), the
 * {@link NoopHeadscalePolicyClient} is wired and the {@link HeadscaleAclReconciler} loop is a
 * compile-only no-op — it NEVER dials headscale and NEVER mutates the mesh. Layer-B (the
 * per-node sshd {@code AuthorizedKeysCommand}, PR #68) remains the load-bearing SSH boundary
 * until a maintainer:
 * <ol>
 *   <li>confirms the canonical machine-key fp field on a live control node (the SAME
 *       {@code docs/CANONICAL-FP.md} blocker the READ side carries — the compiled policy keys
 *       nodes by {@code machine_key_fp}, so it inherits that unverified-field caveat), then</li>
 *   <li>provisions a headscale API key (Vault {@code hugmesh/headscale-admin} property
 *       {@code api-key} via ESO, injected as {@code app.registry.headscale-acl.api-key} —
 *       placeholder-only, NEVER inline), and</li>
 *   <li>flips {@code app.registry.headscale-acl.enabled=true} to make the loop actually push.</li>
 * </ol>
 *
 * <p>Independent of {@link RegistryHeadscaleProperties} ({@code app.registry.headscale.*},
 * the READ/auto-capture flow) so the two legs flip on separately — a deployment may read the
 * pending-node list long before it is ready to let the BFF WRITE the mesh policy. The compile
 * + reconcile contract runs identically against the Noop client (every tick still compiles the
 * desired policy and keeps the last-good text), so the loop is fully unit-testable with no
 * live headscale.
 */
@ConfigurationProperties(prefix = "app.registry.headscale-acl")
public class HeadscaleAclProperties {

    /**
     * Whether the reconcile loop may actually PUSH the compiled policy into headscale. Default
     * <b>false</b> (ships dark) → the {@link NoopHeadscalePolicyClient} is wired and the loop
     * compiles-only (no HTTP, no mesh mutation). Flip to true ONLY after the canonical fp field
     * is live-confirmed + an API key is provisioned.
     */
    private boolean enabled = false;

    /**
     * The headscale control-plane API base URL (the gRPC-gateway REST surface). Only used when
     * {@link #enabled}. Default is the in-cluster headscale service; override per deployment.
     */
    private String baseUrl = "http://headscale.headscale.svc.cluster.local:8080";

    /**
     * The headscale admin API key (Vault {@code hugmesh/headscale-admin} property
     * {@code api-key} via ESO, injected as {@code app.registry.headscale-acl.api-key}).
     * PLACEHOLDER-ONLY — NEVER inline a real key. Blank by default → no {@code Authorization}
     * header (so a recording-ExchangeFunction test exercises the real call shape without a
     * secret); a REAL enabled push against a live headscale REQUIRES a non-blank key.
     */
    private String apiKey = "";

    /**
     * The mesh whose signed device-license export is compiled into the headscale policy. The
     * device-license export is per-mesh; headscale holds ONE policy, so the loop pushes the
     * policy for this configured mesh. Default {@code mesh_default}.
     */
    private String meshId = "mesh_default";

    /** How often the reconcile loop ticks (ms). */
    private long reconcileIntervalMs = 60000;

    /** Initial delay before the first reconcile tick (ms) — lets the context settle. */
    private long reconcileInitialDelayMs = 30000;

    /** Per-call timeout (ms) for a GET/PUT against the headscale policy API. */
    private long timeoutMs = 8000;

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getBaseUrl() { return baseUrl; }
    public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }

    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }

    public String getMeshId() { return meshId; }
    public void setMeshId(String meshId) { this.meshId = meshId; }

    public long getReconcileIntervalMs() { return reconcileIntervalMs; }
    public void setReconcileIntervalMs(long reconcileIntervalMs) { this.reconcileIntervalMs = reconcileIntervalMs; }

    public long getReconcileInitialDelayMs() { return reconcileInitialDelayMs; }
    public void setReconcileInitialDelayMs(long reconcileInitialDelayMs) { this.reconcileInitialDelayMs = reconcileInitialDelayMs; }

    public long getTimeoutMs() { return timeoutMs; }
    public void setTimeoutMs(long timeoutMs) { this.timeoutMs = timeoutMs; }
}
