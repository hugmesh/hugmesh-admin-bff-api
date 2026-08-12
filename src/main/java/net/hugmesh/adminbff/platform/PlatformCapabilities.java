package net.hugmesh.adminbff.platform;

import java.util.List;

/**
 * The platform-capability envelope the admin UI gates its infra-dependent consoles on.
 *
 * <p>Two kinds of fields:
 * <ul>
 *   <li><b>Runtime probes</b> ({@code argocdPresent}, {@code veleroPresent},
 *       {@code buildNodePresent}, {@code imagesGenerated}) — discovered READ-ONLY at
 *       runtime (k8s API / images table). Every probe FAILS SAFE: a k8s error, a missing
 *       client, or no access yields {@code false} plus a human-readable {@link #warnings()}
 *       entry, NEVER an exception or a faked {@code true}. So a deployment that genuinely
 *       lacks the foundational infra (x86 build node → ArgoCD → generated images, plus
 *       Velero) reports the capability ABSENT instead of erroring.</li>
 *   <li><b>Config flags</b> ({@code anubisEnabled}, {@code forumEnabled},
 *       {@code testLaunchEnabled}, {@code casdoorAdminEnabled}, {@code homeserverAdminEnabled})
 *       — mirror the {@code .enabled} switches already in {@code application.yml}. These are
 *       NOT detected from the live cluster; they reflect THIS deployment's configuration.</li>
 * </ul>
 *
 * <p>The UI is the consumer of this envelope; the BFF remains the authoritative gate on every
 * action (defence-in-depth). A capability reported {@code false} here only changes what the UI
 * SHOWS — it never relaxes a server-side authorization or step-up check.
 */
public record PlatformCapabilities(
        // ── runtime probes (read-only, fail-safe) ───────────────────────────────
        boolean argocdPresent,
        boolean veleroPresent,
        boolean buildNodePresent,
        boolean imagesGenerated,
        // ── config flags (mirror application.yml .enabled switches) ──────────────
        boolean anubisEnabled,
        boolean forumEnabled,
        boolean testLaunchEnabled,
        boolean casdoorAdminEnabled,
        boolean homeserverAdminEnabled,
        // ── human-readable notes on anything that could NOT be probed truthfully ─
        List<String> warnings) {

    public PlatformCapabilities {
        // Defensive copy + never-null warnings, so the JSON envelope is always well-formed.
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }
}
