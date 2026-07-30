package systems.hugmesh.adminbff.servicecatalog;

import org.jspecify.annotations.Nullable;

/**
 * Which of the FOUR App-Store service SOURCES a deployment came from + the source's
 * coordinates. The four sources converge on the SAME deploy path (route-access rows +
 * Casdoor role + ArgoCD Application), but two of them need an image BUILT first:
 *
 * <ul>
 *   <li>{@link Kind#SELECT} — a catalog tile referencing a PRE-BUILT image; the
 *       descriptor repo already exists. Works TODAY.</li>
 *   <li>{@link Kind#GIT} — points at an existing git/GitLab repo that already builds its
 *       own image (its own CI). Works TODAY (the effector registers the repo with ArgoCD).</li>
 *   <li>{@link Kind#DOCKERFILE} — a dropped Dockerfile that must be BUILT in-cluster
 *       first. DEPENDS on the Kaniko builder (generator PR) — guarded here.</li>
 *   <li>{@link Kind#ZIP} — an uploaded zip-as-repo that must be BUILT in-cluster first.
 *       DEPENDS on the Kaniko builder — guarded here.</li>
 * </ul>
 *
 * @param kind          the source kind (never null)
 * @param repoUrl       the descriptor/GitOps repo ArgoCD watches (SELECT/GIT: the existing
 *                      repo; DOCKERFILE/ZIP: the repo the Kaniko build would publish into)
 * @param path          the path within the repo ArgoCD syncs (e.g. {@code deploy/}); null → "."
 * @param targetRevision the branch/tag/commit (null → HEAD)
 */
public record ServiceSource(
        Kind kind,
        @Nullable String repoUrl,
        @Nullable String path,
        @Nullable String targetRevision) {

    public enum Kind {
        SELECT, GIT, DOCKERFILE, ZIP;

        /** SELECT + GIT reference a ready image/repo — they deploy TODAY. DOCKERFILE + ZIP
         *  require the in-cluster Kaniko builder (generator) before an image exists. */
        public boolean requiresBuilder() {
            return this == DOCKERFILE || this == ZIP;
        }
    }

    public ServiceSource {
        if (kind == null) {
            throw new IllegalArgumentException("source kind is required");
        }
    }

    /** Parse a source kind from a free-form token (case-insensitive); defaults to SELECT
     *  for a null/blank/unknown token (the safest source — a catalog reference). */
    public static Kind kindOf(@Nullable String token) {
        if (token == null || token.isBlank()) {
            return Kind.SELECT;
        }
        try {
            return Kind.valueOf(token.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return Kind.SELECT;
        }
    }
}
