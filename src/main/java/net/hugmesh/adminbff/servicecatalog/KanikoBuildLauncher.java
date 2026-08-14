package net.hugmesh.adminbff.servicecatalog;

import io.fabric8.kubernetes.api.model.batch.v1.Job;
import io.fabric8.kubernetes.api.model.batch.v1.JobCondition;
import io.fabric8.kubernetes.client.KubernetesClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.servicecatalog.repourl.RepoUrlValidator;
import net.hugmesh.commons.web.ApiException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Builds a service-catalog DOCKERFILE source image in-cluster using Kaniko, then returns
 * the pushed image reference. Wired ONLY when {@code app.appstore.builder.enabled=true}
 * (the DEFAULT is false — SHIPS DARK); the {@link AddServiceEffector} falls back to a
 * 400-guard when this bean is absent.
 *
 * <h3>Build sequence</h3>
 * <ol>
 *   <li>Render the Kaniko Job template (classpath {@code kaniko/service-catalog-build-job.template.yaml})
 *       with the 6 placeholders substituted for this specific {@code brand}/{@code serviceKey} pair.</li>
 *   <li>Create the Job in the build namespace ({@code app.appstore.builder.namespace}) via the
 *       fabric8 {@link KubernetesClient} already on the classpath.</li>
 *   <li>Wait (blocking, on boundedElastic) up to 30 minutes for the Job to reach a terminal
 *       state (succeeded ≥ 1 or failed ≥ 1).</li>
 *   <li>On success return the SHA-tagged {@code destImage}; on failure throw
 *       {@link IllegalStateException} with a diagnostic message.</li>
 * </ol>
 *
 * <h3>Source coverage</h3>
 * Only DOCKERFILE sources are handled here — ZIP sources are rejected with a clear 400
 * ("ZIP source upload is not yet implemented; use DOCKERFILE (git-backed)"). SELECT and
 * GIT sources never reach this class ({@link AddServiceEffector} routes them directly to
 * ArgoCD without a build step).
 *
 * <h3>Reactive boundary</h3>
 * The fabric8 wait is blocking and can take up to 30 minutes. It runs on
 * {@link Schedulers#boundedElastic()} so the event-loop thread is never blocked.
 *
 * <h3>Naming conventions</h3>
 * The Job name is sanitised to the k8s label/DNS-safe lowercase-alphanumeric-with-hyphens
 * charset and suffixed with a 6-character random hex short-SHA to avoid name collisions on
 * rapid retries.
 */
@Component
@ConditionalOnProperty("app.appstore.builder.enabled")
public class KanikoBuildLauncher {

    private static final Logger log = LoggerFactory.getLogger(KanikoBuildLauncher.class);

    /** Hex characters for short-SHA generation — lowercase for DNS-safety. */
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** The classpath template path — must match the file in src/main/resources. */
    private static final String TEMPLATE_PATH = "kaniko/service-catalog-build-job.template.yaml";

    /** Cryptographically random source for the 6-char short-SHA suffix. */
    private static final SecureRandom RANDOM = new SecureRandom();

    /** How long to wait for the Kaniko Job to reach a terminal state. */
    private static final long BUILD_TIMEOUT_MINUTES = 30L;

    private final KubernetesClient k8s;
    private final String buildNamespace;
    private final String registryBase;
    /** Optional host allowlist for the repo URL (LAYER-2 backstop) — mirrors the DTO's
     *  {@code app.appstore.repo-host-allowlist}; empty = any valid host. */
    private final Set<String> repoHostAllowlist;

    public KanikoBuildLauncher(
            KubernetesClient k8s,
            @Value("${app.appstore.builder.namespace:hugmesh-service-catalog-builds}") String buildNamespace,
            @Value("${app.appstore.builder.registry:registry.hugmesh.net}") String registryBase,
            @Value("${app.appstore.repo-host-allowlist:}") String repoHostAllowlistCsv) {
        this.k8s = k8s;
        this.buildNamespace = buildNamespace;
        this.registryBase = registryBase;
        this.repoHostAllowlist = RepoUrlValidator.parseHostAllowlist(repoHostAllowlistCsv);
    }

    /**
     * Build the image for a DOCKERFILE {@link ServiceSource} and return the pushed image reference.
     *
     * <p>ZIP sources are rejected immediately with a 400; all other source-kind routing is done
     * by the caller ({@link AddServiceEffector}). The blocking Kaniko wait runs on
     * {@link Schedulers#boundedElastic()}.
     *
     * @param brand      the brand / domain slug (e.g. {@code acme-test})
     * @param serviceKey the service identifier (e.g. {@code owncast})
     * @param source     the DOCKERFILE-kind source carrying the git context URL
     * @return the SHA-tagged image reference pushed by Kaniko
     */
    public Mono<String> build(final String brand, final String serviceKey, final ServiceSource source) {
        // ZIP source upload is not yet implemented — the caller must use DOCKERFILE (git-backed).
        if (source.kind() == ServiceSource.Kind.ZIP) {
            return Mono.error(ApiException.badRequest(
                    "ZIP source upload is not yet implemented; use DOCKERFILE (git-backed)"));
        }

        // LAYER 2 (defence-in-depth at the SINK): re-run the SAME structural validator the DTO
        // applies (@RepoUrl). The DTO @Valid path already rejects a hostile repoUrl with a 400,
        // but an internal / non-controller caller could reach build() directly with an
        // unvalidated URL. Re-validating HERE — BEFORE the "git://"+repoUrl concat and template
        // substitution — fails the build CLOSED so a file:/http-metadata/host-less/control-char
        // URL never reaches the Kaniko Job context or jobs().load(). Surfaced as a 400.
        RepoUrlValidator.Result repoCheck = RepoUrlValidator.validate(source.repoUrl(), repoHostAllowlist);
        if (!repoCheck.valid()) {
            return Mono.error(ApiException.badRequest("invalid repoUrl: " + repoCheck.reason()));
        }

        // Build the Kaniko context from the git repo URL and optional target revision.
        final String context = "git://" + source.repoUrl()
                + "#" + (source.targetRevision() != null ? source.targetRevision() : "HEAD");

        // The Dockerfile path within the git context — fall back to the root Dockerfile.
        final String dockerfile = source.path() != null ? source.path() + "/Dockerfile" : "Dockerfile";

        // A 6-char lowercase hex short-SHA keeps Job names unique across rapid retries.
        final String shortSha = randomShortSha();

        // The Job name is the brand + service + shortSha, sanitised to k8s-safe form.
        final String buildName = sanitiseName(brand + "-" + serviceKey + "-" + shortSha);

        // SHA-tagged image — the precise image the ArgoCD Application will deploy.
        final String destImage = registryBase + "/" + brand + "/" + serviceKey + ":" + shortSha;

        // Branch/moving tag — convenient alias pushed alongside the immutable SHA tag.
        final String destMoving = registryBase + "/" + brand + "/" + serviceKey + ":"
                + (source.targetRevision() != null ? source.targetRevision() : "main");

        log.info("[kaniko-builder] queueing build '{}' (context={}, image={}, movingTag={})",
                buildName, context, destImage, destMoving);

        // Wrap the blocking Kaniko Job create + wait on boundedElastic so the event loop is free.
        return Mono.fromCallable(() -> launchAndWait(buildName, context, dockerfile, destImage, destMoving))
                .subscribeOn(Schedulers.boundedElastic());
    }

    // ── Blocking build leg (runs on boundedElastic) ──────────────────────────

    /**
     * Apply the rendered Kaniko Job to the cluster, wait for it to reach a terminal state, then
     * return the SHA-tagged {@code destImage} on success or throw on failure/timeout.
     *
     * <p>This method is BLOCKING and must only be called from a boundedElastic thread.
     */
    private String launchAndWait(final String buildName, final String context, final String dockerfile,
                                 final String destImage, final String destMoving) {
        // Load and render the Kaniko Job YAML template from the classpath.
        String rendered = renderTemplate(buildName, buildNamespace, context, dockerfile, destImage, destMoving);

        // Parse the rendered YAML into a typed Fabric8 Job and create it in the build namespace.
        Job job;
        try (var stream = new ByteArrayInputStream(rendered.getBytes(StandardCharsets.UTF_8))) {
            job = k8s.batch().v1().jobs()
                    .inNamespace(buildNamespace)
                    .load(stream)
                    .create();
            log.info("[kaniko-builder] Job '{}' created in namespace '{}'", buildName, buildNamespace);
        } catch (Exception e) {
            // A cluster-side rejection (RBAC, admission, conflict) is surfaced as IllegalStateException
            // so the effector can report a meaningful failure to the caller.
            throw new IllegalStateException(
                    "could not create Kaniko Job '" + buildName + "': " + e.getMessage(), e);
        }

        // Wait (blocking) up to BUILD_TIMEOUT_MINUTES for the Job to succeed or fail.
        job = k8s.batch().v1().jobs()
                .inNamespace(buildNamespace)
                .withName(buildName)
                .waitUntilCondition(KanikoBuildLauncher::isTerminal, BUILD_TIMEOUT_MINUTES, TimeUnit.MINUTES);

        // Null return from waitUntilCondition means the condition was never met (timeout).
        if (job == null) {
            throw new IllegalStateException(
                    "Kaniko Job '" + buildName + "' did not complete within " + BUILD_TIMEOUT_MINUTES + " minutes");
        }

        // Check whether the Job succeeded or failed and return/throw accordingly.
        if (isSucceeded(job)) {
            log.info("[kaniko-builder] Job '{}' succeeded → pushed image '{}'", buildName, destImage);
            return destImage;
        }
        // Job reached a terminal state but did not succeed — report a clear failure.
        throw new IllegalStateException(
                "Kaniko Job '" + buildName + "' failed (check pod logs in namespace '" + buildNamespace + "')");
    }

    // ── Template rendering ────────────────────────────────────────────────────

    /**
     * Load the Kaniko Job template from the classpath and substitute the 6 placeholders.
     * Throws {@link IllegalStateException} if the template file is missing (a packaging error).
     */
    private static String renderTemplate(final String buildName, final String buildNamespace,
                                         final String context, final String dockerfile,
                                         final String destImage, final String destMoving) {
        String template;
        try {
            byte[] bytes = new ClassPathResource(TEMPLATE_PATH).getInputStream().readAllBytes();
            template = new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Kaniko Job template missing from classpath: " + TEMPLATE_PATH, e);
        }
        // Substitute all 6 placeholders in the template — each placeholder maps 1-to-1 to the
        // value the caller computed for this specific brand/service/sha combination.
        //
        // DEFENCE-IN-DEPTH: ${CONTEXT}/${DOCKERFILE}/${DEST_IMAGE_MOVING} are composed from the
        // client-supplied repoUrl/path/targetRevision. Those fields are already @Pattern-locked on
        // the request DTO (ProvisionServiceRequest), but we re-check the COMPOSED values here so a
        // value that ever reached this point by another path cannot break out of the Kaniko arg
        // scalar and inject extra args (e.g. --destination to an attacker registry) or sibling Job
        // keys. A YAML-breaking char (quote/newline/control) THROWS before client.load(), failing
        // the build closed rather than applying a poisoned manifest. buildName is already sanitised;
        // buildNamespace/destImage are server-derived.
        return template
                .replace("${BUILD_NAME}", buildName)
                .replace("${BUILD_NAMESPACE}", buildNamespace)
                .replace("${CONTEXT}", yamlSafe("context", context))
                .replace("${DOCKERFILE}", yamlSafe("dockerfile", dockerfile))
                .replace("${DEST_IMAGE}", destImage)
                .replace("${DEST_IMAGE_MOVING}", yamlSafe("destImageMoving", destMoving));
    }

    /**
     * Render-time guard: reject (throw) if a value to be substituted into a quoted YAML arg scalar
     * still carries a YAML-breaking character — a double/single quote, backslash, CR, LF or any
     * other ISO control character. This is the defence-in-depth backstop to the DTO {@code @Pattern}
     * allowlists on repoUrl/path/targetRevision; it runs BEFORE the manifest is parsed/applied, so
     * an injection attempt fails the build closed instead of producing a poisoned Job. Returns the
     * value unchanged when safe.
     */
    static String yamlSafe(final String field, final String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\'' || c == '\\' || Character.isISOControl(c)) {
                throw new IllegalStateException(
                        "Kaniko manifest value '" + field + "' contains an illegal character");
            }
        }
        return value;
    }

    // ── Job terminal-state predicates (referenced as :: method refs) ──────────

    /**
     * True when the Job has reached a terminal state — either succeeded or failed.
     * Used as the {@code waitUntilCondition} predicate so the wait unblocks as soon as
     * the cluster reports a definitive outcome.
     */
    static boolean isTerminal(final Job job) {
        return isSucceeded(job) || isFailed(job);
    }

    /**
     * True when the Job's {@code status.succeeded} count is ≥ 1 (at least one Pod completed
     * successfully). This is the canonical Kubernetes indicator for a finished batch Job.
     */
    static boolean isSucceeded(final Job job) {
        return job != null
                && job.getStatus() != null
                && job.getStatus().getSucceeded() != null
                && job.getStatus().getSucceeded() >= 1;
    }

    /**
     * True when the Job has failed — either its {@code status.failed} count is ≥ 1 OR any
     * {@code status.conditions} entry has {@code type=Failed} and {@code status=True}.
     */
    static boolean isFailed(final Job job) {
        if (job == null || job.getStatus() == null) {
            return false;
        }
        // A non-zero failed count means at least one Pod exhausted its retry budget.
        if (job.getStatus().getFailed() != null && job.getStatus().getFailed() >= 1) {
            return true;
        }
        // An explicit Failed condition is the other authoritative failure signal.
        List<JobCondition> conditions = job.getStatus().getConditions();
        if (conditions == null) {
            return false;
        }
        return conditions.stream()
                .anyMatch(c -> "Failed".equals(c.getType()) && "True".equals(c.getStatus()));
    }

    // ── Name helpers ──────────────────────────────────────────────────────────

    /**
     * Sanitise a raw name to the k8s/DNS-safe lowercase-alphanumeric-with-hyphens charset:
     * lowercase the input, replace non-{@code [a-z0-9-]} characters with {@code -}, collapse
     * consecutive hyphens, and strip leading/trailing hyphens. An empty result collapses to
     * the stable sentinel {@code "x"}.
     */
    private static String sanitiseName(final String raw) {
        if (raw == null) {
            return "x";
        }
        String s = raw.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9-]", "-")
                .replaceAll("-+", "-")
                .replaceAll("(^-+)|(-+$)", "");
        return s.isEmpty() ? "x" : s;
    }

    /**
     * Generate a 6-character lowercase hex string from {@link SecureRandom} — the short-SHA
     * suffix that keeps Job names unique across rapid retries for the same brand/service pair.
     */
    private static String randomShortSha() {
        byte[] bytes = new byte[3];   // 3 bytes → 6 hex characters
        RANDOM.nextBytes(bytes);
        char[] hex = new char[6];
        for (int i = 0; i < 3; i++) {
            int b = bytes[i] & 0xff;
            hex[i * 2]     = HEX[b >>> 4];
            hex[i * 2 + 1] = HEX[b & 0x0f];
        }
        return new String(hex);
    }
}
