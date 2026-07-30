package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;
import systems.hugmesh.adminbff.servicecatalog.repourl.RepoUrl;

/**
 * Body for {@code POST /bff/superadmin/service-store/{domain}/deployments/{id}/provision}
 * (SUPERADMIN) — drive an existing {@code service_deployment} row into a real provisioned
 * service via the {@link systems.hugmesh.adminbff.servicecatalog.AddServiceEffector}.
 *
 * <p>Describes WHICH of the four App-Store sources the service came from + the GitOps repo
 * coordinates ArgoCD watches:
 * <ul>
 *   <li>{@code sourceKind} — one of {@code SELECT}/{@code GIT}/{@code DOCKERFILE}/{@code ZIP}
 *       (case-insensitive; null/blank → SELECT). DOCKERFILE/ZIP are guarded until the Kaniko
 *       builder exists.</li>
 *   <li>{@code repoUrl} — the descriptor/GitOps repo (required for SELECT/GIT).</li>
 *   <li>{@code path} — the path within the repo ArgoCD syncs (null → ".").</li>
 *   <li>{@code targetRevision} — the branch/tag/commit (null → HEAD).</li>
 * </ul>
 */
public record ProvisionServiceRequest(
        @Size(max = 32, message = "sourceKind is too long")
        @Nullable
        String sourceKind,

        @NotBlank(message = "repoUrl is required")
        @Size(max = 512, message = "repoUrl is too long")
        // LAYER 1a — charset allowlist (PR #174): this value is composed into the Kaniko
        // --context arg scalar of a YAML Job manifest (KanikoBuildLauncher.renderTemplate).
        // Reject quotes, newlines and other control characters that could break out of the arg
        // scalar and inject extra Kaniko args or sibling Job keys — the YAML/Job-spec injection
        // guard. Git/URL charset.
        @Pattern(regexp = "^[A-Za-z0-9._:/#?=&@~+-]{1,512}$",
                message = "repoUrl contains invalid characters")
        // LAYER 1b — STRUCTURAL SSRF guard (this PR): the charset check is blind to URL
        // structure, so file:///etc/passwd, http://169.254.169.254/... (cloud-metadata SSRF)
        // and host-less git:// all pass it. @RepoUrl parses the URL and enforces scheme ∈
        // {https, git, ssh}, a non-empty host, and (when app.appstore.repo-host-allowlist is
        // set) a host on the allowlist. KanikoBuildLauncher re-runs the same RepoUrlValidator
        // at the sink (LAYER 2) so an internal caller cannot bypass this DTO layer.
        @RepoUrl
        String repoUrl,

        @Size(max = 256, message = "path is too long")
        // Allowlist charset: composed into the Kaniko --dockerfile arg scalar — same YAML
        // hardening as repoUrl. A safe relative path charset (no quotes/newlines/control chars).
        @Pattern(regexp = "^[A-Za-z0-9._/-]{1,256}$",
                message = "path contains invalid characters")
        @Nullable
        String path,

        @Size(max = 128, message = "targetRevision is too long")
        // Allowlist charset: composed into the Kaniko --context arg scalar (and a moving image
        // tag) — same YAML hardening. Git ref charset (branch/tag/commit).
        @Pattern(regexp = "^[A-Za-z0-9._/-]{1,128}$",
                message = "targetRevision contains invalid characters")
        @Nullable
        String targetRevision) {
}
