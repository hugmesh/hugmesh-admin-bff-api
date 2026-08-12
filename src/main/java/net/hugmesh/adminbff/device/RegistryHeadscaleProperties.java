package net.hugmesh.adminbff.device;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the HEADSCALE-ANCHORED machine_key_fp AUTO-CAPTURE flow (the
 * device-license-registry "headscale-anchored hybrid"). Headscale is the trust gate that
 * MINTS the machine keys; the SUPERADMIN assigns owner_type/domain/image_type from a
 * headscale-backed PENDING pick-list and the fingerprint is an OPAQUE token captured from
 * headscale (never hand-typed, never normalised). On register the BFF RE-QUERIES headscale
 * to re-validate the offered fingerprint (still enrolled + meshId matches) before it stamps
 * the row, so {@code device_registry.machine_key_fp == headscale fp == node baked fp} —
 * one string, zero human keystrokes.
 *
 * <h3>⚠ SHIPS DARK / ADVISORY (PR-0 BLOCKER)</h3>
 * <b>Which headscale field is CANONICAL (machineKey vs nodeKey) cannot be confirmed in this
 * environment — it needs a LIVE headscale control node.</b> provision.sh bakes the node's
 * {@code .Self.PublicKey} (the NODE key) and the Layer-A force-tags reaches for
 * {@code .machineKey // .nodeKey} ambiguously. Copying the WRONG field FAITHFULLY would
 * fail-closed-DENY EVERYONE. So:
 * <ul>
 *   <li>{@link #getFpField() fp-field} is a CONFIG PARAMETER (not hard-coded). The default
 *       is the design's best guess that MATCHES what provision.sh already bakes —
 *       {@code .Self.PublicKey}, which {@code headscale nodes list -o json} surfaces under
 *       the {@code nodeKey} field. Until a maintainer confirms the canonical field on a live
 *       control node and freezes it in {@code docs/CANONICAL-FP.md}, this is unverified.</li>
 *   <li>{@link #isAllowManualFp() allow-manual-fp} is a BREAK-GLASS escape hatch, default
 *       <b>ON</b> (true): the headscale re-validation on register is ADVISORY — if it fails
 *       (or headscale is unreachable, or the fp field is wrong) the manual/opaque fingerprint
 *       supplied by the superadmin is accepted anyway, with a loud WARN. The boundary is NOT
 *       load-bearing until a maintainer (1) confirms the canonical fp field on a live node,
 *       (2) freezes it in {@code docs/CANONICAL-FP.md}, then (3) flips
 *       {@code app.registry.headscale.allow-manual-fp=false} to make re-validation
 *       enforcing. Layer-B (per-node sshd, PR #68) remains the load-bearing boundary
 *       meanwhile.</li>
 * </ul>
 *
 * <p>{@link #isEnabled() enabled} gates whether the {@link HeadscaleNodesClient} shells out
 * to {@code headscale nodes list -o json} at all. Default <b>false</b> so a deployment with
 * no headscale binary (CI, dev, every existing test) boots clean: {@code GET /pending} then
 * returns the registry-only view (no enrolled-but-unregistered nodes) and register skips the
 * re-query (advisory accept, exactly the break-glass default).
 */
@ConfigurationProperties(prefix = "app.registry.headscale")
public class RegistryHeadscaleProperties {

    /** The provision.sh / Layer-B baked default: the node-key the node reads from
     *  {@code tailscale status --json .Self.PublicKey}, surfaced by
     *  {@code headscale nodes list -o json} under {@code nodeKey}. SEE THE CLASS JAVADOC —
     *  this is the design's best guess, NOT a live-confirmed canonical choice. */
    public static final String DEFAULT_FP_FIELD = "nodeKey";

    /** Whether to invoke the headscale CLI at all (false => no enrolled-node enumeration;
     *  pending list is registry-only and register re-query is skipped/advisory). */
    private boolean enabled = false;

    /** Absolute path to the headscale binary (only used when {@link #enabled}). */
    private String binary = "/usr/bin/headscale";

    /**
     * Which JSON field of {@code headscale nodes list -o json} carries the canonical
     * machine-key fingerprint. ⚠ CONFIG PARAMETER, not hard-coded — confirm on a live
     * control node and freeze in {@code docs/CANONICAL-FP.md} before enforcing. Default
     * {@link #DEFAULT_FP_FIELD} (matches provision.sh's baked {@code .Self.PublicKey}).
     */
    private String fpField = DEFAULT_FP_FIELD;

    /**
     * BREAK-GLASS: accept the superadmin-supplied opaque fingerprint EVEN WHEN the headscale
     * re-validation on register fails / is unavailable. Default <b>true</b> (ships dark) —
     * the re-validation is advisory until the canonical fp field is live-confirmed and frozen,
     * then flip to {@code false} to make register fail-closed (409) on a mismatch.
     */
    private boolean allowManualFp = true;

    /** Timeout (ms) for the headscale CLI invocation. */
    private long timeoutMs = 8000;

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getBinary() { return binary; }
    public void setBinary(String binary) { this.binary = binary; }

    public String getFpField() { return fpField; }
    public void setFpField(String fpField) { this.fpField = fpField; }

    public boolean isAllowManualFp() { return allowManualFp; }
    public void setAllowManualFp(boolean allowManualFp) { this.allowManualFp = allowManualFp; }

    public long getTimeoutMs() { return timeoutMs; }
    public void setTimeoutMs(long timeoutMs) { this.timeoutMs = timeoutMs; }
}
