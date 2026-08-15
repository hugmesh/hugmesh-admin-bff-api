package net.hugmesh.adminbff.device;

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
 *   <li>provisions a headscale API key (Vault {@code snapdragon/headscale-admin} property
 *       {@code api-key} via ESO, injected as {@code app.registry.headscale-acl.api-key} —
 *       placeholder-only, NEVER inline; NOTE no ExternalSecret or deployment env for this
 *       exists in the cluster tree yet), and</li>
 *   <li>SETTLES THE SINGLE-WRITER QUESTION and records the answer in {@link #getPolicyMode()}.
 *       The fleet ships {@code policy: mode: file} with the node-side renderer as the writer;
 *       {@code PUT /api/v1/policy} only works in DB mode. Leaving {@code policy-mode=file}
 *       (the default) while flipping {@code enabled=true} now FAILS THE CONTEXT with a message
 *       naming the mismatch, instead of 4xx-ing silently forever, and</li>
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
     * {@link #enabled}. Default is THIS platform's in-cluster headscale Service; override per
     * deployment.
     *
     * <p>CORRECTED 2026-07-30: the default was {@code headscale.headscale.svc.cluster.local},
     * a namespace this platform does not have. headscale runs as a HOST OpenRC service on the
     * pki node and is exposed in-cluster by a selector-less Service {@code headscale} in
     * namespace {@code hugmesh-pki} (hugmesh-generator
     * {@code specs/cluster/manifests/headscale/service.yaml}, Application destination namespace
     * {@code hugmesh-pki} in {@code specs/cluster/apps/07-headscale-svc.yaml}); the pki gateway
     * dials exactly this URL ({@code specs/cluster/apps/20-gateway-pki.yaml}). The old default
     * would have resolved to nothing, so an enabled push would have failed DNS every tick —
     * indistinguishable, in the logs, from headscale simply being down.
     */
    private String baseUrl = "http://headscale.hugmesh-pki.svc.cluster.local:8080";

    /**
     * The policy mode the TARGET headscale runs in — {@code file} or {@code db}. This is NOT a
     * knob that changes what this BFF does; it is the operator's DECLARATION of the deployment
     * it is pointing at, and it exists so the file-vs-DB single-writer mismatch FAILS LOUDLY AND
     * EARLY instead of degrading into a silent, permanent no-op.
     *
     * <p>Default {@code file}, because that is what the fleet actually ships: hugmesh-generator
     * {@code specs/etc/headscale/config.yaml} sets {@code policy: {mode: file, path:
     * /etc/headscale/policy.hujson}}, and the node-side renderer
     * {@code specs/usr/sbin/gen-headscale-policy.sh} is the single writer of that file
     * ({@code headscale policy set -f}). {@code PUT /api/v1/policy} — the only write this BFF
     * has — is a DB-MODE-ONLY call that headscale rejects with 4xx in file mode.
     *
     * <p>Consequence, enforced in {@link HeadscaleAclConfig}: with {@link #enabled} true and this
     * still {@code file}, the push client REFUSES TO BE WIRED and the context fails to start with
     * a message naming the mismatch. Setting it to {@code db} is an ASSERTION that headscale was
     * moved to DB mode AND that the node-side {@code hugmesh-policy-sync} writer was disabled —
     * two writers against one policy would flap the mesh.
     */
    private String policyMode = "file";

    /**
     * The node-local privileged unix account a tailnet-SSH session opens AS — the {@code users}
     * value of every compiled ssh rule. Mirrors the node renderer's {@code TS_SSH_USER}
     * (hugmesh-generator {@code specs/etc/keys-provision/provision.sh} {@code resolve_ssh_user},
     * whose own fallback is {@code admin}). A value that does not match the node's resolved
     * account yields edges no session can use, so this must be set to whatever
     * {@code .tailscale.ssh_user} resolved to for the fleet.
     */
    private String sshUser = "admin";

    /**
     * The headscale admin API key (Vault {@code snapdragon/headscale-admin} property
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

    public String getPolicyMode() { return policyMode; }
    public void setPolicyMode(String policyMode) { this.policyMode = policyMode; }

    public String getSshUser() { return sshUser; }
    public void setSshUser(String sshUser) { this.sshUser = sshUser; }

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
