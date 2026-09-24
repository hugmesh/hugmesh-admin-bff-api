package net.hugmesh.adminbff.device;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the LAYER-A headscale ACL PUSH client + reconcile loop — the leg that
 * COMPILES the signed device-license export into a headscale ACL policy and PUSHES it into
 * headscale via its policy API ({@code PUT /api/v1/policy}). This is the WRITE counterpart to
 * the READ-ONLY {@link HeadscaleNodesClient}: that one reads {@code headscale nodes list};
 * this one writes the mesh's authorized-SSH edges as a headscale policy.
 *
 * <h3>THE SINGLE WRITER IS THIS BFF (decision 101 = B, 2026-09-23)</h3>
 * The tailnet ACL policy has exactly ONE writer: this BFF's direct {@code PUT /api/v1/policy}.
 * headscale keeps the policy in its DATABASE ({@code policy: mode: database} — headscale's own
 * spelling, see {@link #getPolicyMode()}). The node-side agent that used to own it —
 * hugmesh-generator {@code specs/usr/sbin/gen-headscale-policy.sh}, run every 60 s by the
 * {@code hugmesh-policy-sync} cron on the control node, rendering {@code policy.hujson} for a
 * {@code policy: mode: file} headscale — is RETIRED as a writer by that decision. Removing it
 * and moving the control node's {@code specs/etc/headscale/config.yaml} to
 * {@code mode: database} is generator-side work that has NOT landed yet; until it does, the
 * fleet as built still runs the retired agent in file mode, which is one more reason this leg
 * stays dark (below). Two writers against one policy would flap the mesh, so the generator
 * cut-over and flipping {@link #isEnabled() enabled} have to happen together.
 *
 * <h3>⚠ SHIPS DARK / OFF BY DEFAULT (Layer-B is the load-bearing boundary)</h3>
 * {@link #isEnabled() enabled} defaults <b>false</b>: with no headscale control node and no
 * configured API key (CI, dev, every existing test, a fresh single-stick deployment), the
 * {@link NoopHeadscalePolicyClient} is wired and the {@link HeadscaleAclReconciler} loop is a
 * compile-only no-op — it NEVER dials headscale and NEVER mutates the mesh. Layer-B (the
 * per-node sshd {@code AuthorizedKeysCommand}) remains the load-bearing SSH boundary until a
 * maintainer:
 * <ol>
 *   <li>confirms the canonical machine-key fp field on a live control node (the SAME
 *       {@code docs/CANONICAL-FP.md} blocker the READ side carries — the compiled policy keys
 *       nodes by {@code machine_key_fp}, so it inherits that unverified-field caveat),</li>
 *   <li>provisions a headscale API key (Vault {@code hugmesh/headscale-admin} property
 *       {@code api-key} via ESO, injected as {@code app.registry.headscale-acl.api-key} —
 *       placeholder-only, NEVER inline; NOTE no ExternalSecret or deployment env for this
 *       exists in the cluster tree yet),</li>
 *   <li>lands the generator cut-over: the control node's headscale runs
 *       {@code policy: mode: database} with its policy table SEEDED (a database-mode headscale
 *       with no stored policy runs with NO filter at all — allow-all — until the first
 *       successful PUT), and the {@code hugmesh-policy-sync} agent is gone, and then</li>
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
     * is live-confirmed, an API key is provisioned, and the control node runs headscale in
     * {@code policy: mode: database} with the node-side {@code hugmesh-policy-sync} agent
     * removed (see the class javadoc).
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
     * The policy mode the TARGET headscale runs in, spelled EXACTLY as headscale's own
     * {@code policy.mode} config value: {@code database} or {@code file}. This is NOT a knob
     * that changes what this BFF does; it is the operator's DECLARATION of the deployment it is
     * pointing at, and it exists so a file-vs-database mismatch FAILS LOUDLY AND EARLY instead
     * of degrading into a silent, permanent no-op.
     *
     * <p>Default {@code database}, because decision 101 = B (2026-09-23) made this BFF's
     * {@code PUT /api/v1/policy} the ONLY writer of the tailnet policy, and that call is
     * database-mode-only: headscale v0.23.0 ({@code HEADSCALE_VERSION} pinned by
     * hugmesh-generator) answers {@code SetPolicy} with {@code ErrPolicyUpdateIsDisabled}
     * unless {@code cfg.Policy.Mode == "database"} ({@code hscontrol/grpcv1.go}; the constant is
     * {@code types.PolicyModeDB = "database"} in {@code hscontrol/types/config.go}).
     *
     * <p>WHY NOT {@code db}: this BFF used to spell the mode {@code db}. headscale does not
     * know that word — v0.23.0's {@code loadACLPolicy} hits its {@code default:} branch and
     * {@code log.Fatal}s with "Unknown ACL policy mode", so a control node configured by copying
     * this property's old value would never start. The declaration therefore uses headscale's
     * spelling verbatim and {@code db} is refused.
     *
     * <p>Consequence, enforced in {@link HeadscaleAclConfig}: with {@link #enabled} true and
     * this anything but {@code database} (in particular {@code file}), the push client REFUSES
     * TO BE WIRED and the context fails to start with a message naming the mismatch. Declaring
     * {@code database} is an ASSERTION that the control node's headscale actually runs
     * {@code policy: mode: database} and that the retired node-side {@code hugmesh-policy-sync}
     * writer is gone — the default states the decided target, and it only becomes TRUE of the
     * fleet once the generator cut-over lands (see the class javadoc).
     */
    private String policyMode = "database";

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
